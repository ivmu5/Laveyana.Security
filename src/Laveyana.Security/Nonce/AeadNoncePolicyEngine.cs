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
    /// Maximum randomized invocations over the supported, freshly generated key lifetime.
    /// A different backend instance cannot resume this lifetime from persisted key material.
    /// </summary>
    internal const long MaxRandomizedInvocationsPerKeyLifetime = 1L << 20;

    /// <summary>The maximum managed plaintext length in one future whole-buffer operation.</summary>
    internal const long MaxPlaintextBytes = 64L * 1024 * 1024;

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
            if (context.Origin != AeadKeyOrigin.FreshlyGenerated &&
                context.ProviderGuarantee != AeadProviderNonceGuarantee.OwnsNonceLifecycleIncludingImportedHistory)
            {
                throw new CryptographicException("The provider has not established imported-key nonce safety.");
            }

            // A remote/HSM backend may support AES-GCM even where local AesGcm does not.
            return AeadNonceStrategy.ProviderManaged;
        }

        AlgorithmPolicy.EnsureAllowed(context.Algorithm, AlgorithmPurpose.AuthenticatedEncryption,
            AlgorithmUse.NewOperation);

        if (context.Origin != AeadKeyOrigin.FreshlyGenerated)
        {
            throw new CryptographicException("AES key nonce history is unknown; generate a new key version before forward encryption.");
        }

        // Neither a capability bit nor an allocator interface attests to independent,
        // key-wide reservation history. No verified deterministic profile is shipped.
        // Supplying an allocator must never silently fall back to randomized issuance.
        if (context.Allocator is not null)
        {
            throw new CryptographicException(
                "Deterministic AES-GCM nonce allocation is disabled: an independently verified key-wide allocator profile is unavailable.");
        }

        if (context.RandomizedBudget is null)
        {
            throw new CryptographicException("A live, fresh-key lifetime budget is required for randomized AES-GCM encryption.");
        }

        return AeadNonceStrategy.Randomized;
    }

    /// <summary>Creates a key-scoped issuer after strategy validation.</summary>
    internal static AeadNonceSession Create(AeadNoncePolicyContext context)
    {
        AeadNonceStrategy strategy = Select(context);
        NonceBudget? budget = strategy == AeadNonceStrategy.Randomized ? context.RandomizedBudget : null;
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

    /// <summary>Atomic lifetime counter; it is never reconstructed from persisted metadata.</summary>
    internal sealed class NonceBudget
    {
        private long _issued;

        internal NonceBudget(long alreadyIssued = 0)
        {
            if (alreadyIssued < 0 || alreadyIssued > MaxRandomizedInvocationsPerKeyLifetime)
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
                if (current >= MaxRandomizedInvocationsPerKeyLifetime)
                {
                    throw new CryptographicException("AES-GCM key lifetime randomized nonce budget exhausted; generate a new key version.");
                }

                if (Interlocked.CompareExchange(ref _issued, current + 1, current) == current)
                {
                    return;
                }
            }
        }
    }
}
