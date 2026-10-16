using System.Collections.Concurrent;
using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Algorithms;

namespace Laveyana.Security.Nonce;

/// <summary>
/// Selects an AES-256-GCM nonce strategy without automatic downgrade. This is a low-level
/// operation primitive, not an authorization decision or a full encryption service.
/// </summary>
internal static class AeadNoncePolicyEngine
{
    /// <summary>
    /// A conservative, per-process per-key randomized nonce budget. Across restarts,
    /// independent processes and restores, the application must enforce key lifetime limits.
    /// </summary>
    internal const long MaxRandomizedInvocationsPerProcessKey = 1L << 20;

    /// <summary>The maximum managed plaintext length in one future whole-buffer operation.</summary>
    internal const long MaxPlaintextBytes = 64L * 1024 * 1024;

    private static readonly ConcurrentDictionary<KeyReference, NonceBudget> RandomBudgets = new();

    /// <summary>Evaluates trusted backend characteristics for one exact key version.</summary>
    internal static AeadNonceStrategy Select(AeadNoncePolicyContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!context.Reference.IsDefined || context.StoreCapabilities is null ||
            !Enum.IsDefined(context.Origin) || !Enum.IsDefined(context.RestoreState) ||
            !Enum.IsDefined(context.ProviderGuarantee))
        {
            throw new ArgumentException("Nonce policy context is invalid.", nameof(context));
        }

        if (context.Algorithm != WellKnownAlgorithms.Aes256Gcm)
        {
            throw new CryptographicException("This nonce policy supports AES-256-GCM only.");
        }

        if (context.RestoreState != AeadRestoreState.Clean)
        {
            throw new CryptographicException("A restored key generation requires reconciliation or a new KeyId.");
        }

        if (context.ProviderGuarantee != AeadProviderNonceGuarantee.None)
        {
            if (context.Origin == AeadKeyOrigin.ImportedUnknownNonceHistory &&
                context.ProviderGuarantee != AeadProviderNonceGuarantee.OwnsNonceLifecycleIncludingImportedHistory)
            {
                throw new CryptographicException("The provider has not established imported-key nonce safety.");
            }

            // A remote/HSM backend may support AES-GCM even where local AesGcm does not.
            return AeadNonceStrategy.ProviderManaged;
        }

        AlgorithmPolicy.EnsureAllowed(context.Algorithm, AlgorithmPurpose.AuthenticatedEncryption,
            AlgorithmUse.NewOperation);

        if (context.Origin == AeadKeyOrigin.ImportedUnknownNonceHistory)
        {
            throw new CryptographicException("Imported AES keys with unknown nonce history cannot be used for managed encryption.");
        }

        // Rollback protection and a separate allocator are BOTH necessary, not individually sufficient.
        // Do not fall back to a randomized nonce if a supplied allocator is unavailable or fails.
        if (context.Allocator is not null)
        {
            if (!context.StoreCapabilities.ProvidesRollbackProtection)
            {
                throw new CryptographicException("Deterministic nonce allocation requires rollback-protected state.");
            }

            return AeadNonceStrategy.RollbackProtectedDeterministic;
        }

        return AeadNonceStrategy.Randomized;
    }

    /// <summary>Creates a key-scoped issuer after strategy validation.</summary>
    internal static AeadNonceSession Create(AeadNoncePolicyContext context)
    {
        AeadNonceStrategy strategy = Select(context);
        NonceBudget? budget = strategy == AeadNonceStrategy.Randomized
            ? RandomBudgets.GetOrAdd(context.Reference, static _ => new NonceBudget())
            : null;
        return new AeadNonceSession(context.Reference, strategy, context.Allocator, budget);
    }

    /// <summary>Checks per-message bounds before issuing an AES-GCM nonce.</summary>
    internal static void ValidatePlaintextLength(long length)
    {
        if (length < 0 || length > MaxPlaintextBytes)
        {
            throw new CryptographicException("AES-GCM plaintext length exceeds the supported whole-buffer limit.");
        }
    }

    /// <summary>Atomic per-process counter; a rejected attempt consumes no nonce.</summary>
    internal sealed class NonceBudget
    {
        private long _issued;

        internal NonceBudget(long alreadyIssued = 0)
        {
            if (alreadyIssued < 0 || alreadyIssued > MaxRandomizedInvocationsPerProcessKey)
            {
                throw new ArgumentOutOfRangeException(nameof(alreadyIssued));
            }

            _issued = alreadyIssued;
        }

        internal void Consume()
        {
            while (true)
            {
                long current = Interlocked.Read(ref _issued);
                if (current >= MaxRandomizedInvocationsPerProcessKey)
                {
                    throw new CryptographicException("Per-process AES-GCM randomized nonce budget exhausted; re-key.");
                }

                if (Interlocked.CompareExchange(ref _issued, current + 1, current) == current)
                {
                    return;
                }
            }
        }
    }
}
