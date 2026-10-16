using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Payloads;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Algorithms;

namespace Laveyana.Security.Signatures;

/// <summary>
/// Managed signing adapter for a provider-owned, exact-version private/public key executor.
/// The supplied provider remains responsible for authoritative metadata and key revocation.
/// </summary>
public sealed class ManagedSignatureBackend : IManagedSignatureBackend
{
    private readonly IKeyProviderBackend _metadata;
    private readonly IVersionedSignatureKeyOperations _keys;

    /// <summary>Wraps one metadata backend and its trusted signature executor.</summary>
    public ManagedSignatureBackend(IKeyProviderBackend metadata, IVersionedSignatureKeyOperations keys)
    {
        _metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        _keys = keys ?? throw new ArgumentNullException(nameof(keys));
        if (!metadata.ProviderId.IsDefined)
        {
            throw new ArgumentException("Provider identity is undefined.", nameof(metadata));
        }
    }

    /// <summary>Gets the immutable owner identity.</summary>
    public ProviderId ProviderId => _metadata.ProviderId;

    /// <summary>Returns declarations; operation-time checks are still mandatory.</summary>
    public ValueTask<ProviderCapabilitySnapshot> GetCapabilitiesAsync(CancellationToken cancellationToken = default) =>
        _metadata.GetCapabilitiesAsync(cancellationToken);

    /// <summary>Returns logical metadata without interpreting aliases.</summary>
    public ValueTask<KeyDescriptor?> FindLogicalAsync(LogicalKeyHandle handle, CancellationToken cancellationToken = default) =>
        _metadata.FindLogicalAsync(handle, cancellationToken);

    /// <summary>Returns exact metadata without changing version.</summary>
    public ValueTask<KeyVersionDescriptor?> FindExactAsync(ExactKeyHandle handle, CancellationToken cancellationToken = default) =>
        _metadata.FindExactAsync(handle, cancellationToken);

    /// <summary>Signs with a freshly resolved Active private key. Does not expose private bytes.</summary>
    public ValueTask<SignaturePayload> SignAsync(LogicalKeyHandle handle, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default)
    {
        ValidateHandle(handle);
        CheckMessage(message.Length);
        cancellationToken.ThrowIfCancellationRequested();
        return WithMessageSnapshotAsync(message,
            captured => SignCoreAsync(handle, captured, cancellationToken));
    }

    private async ValueTask<SignaturePayload> SignCoreAsync(LogicalKeyHandle handle,
        ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        KeyDescriptor logical = await _metadata.FindLogicalAsync(handle, cancellationToken).ConfigureAwait(false)
            ?? throw new CryptographicException("Signing key is unavailable.");
        if (logical.ProviderId != ProviderId || logical.KeyId != handle.KeyId ||
            logical.Kind != KeyKind.AsymmetricPrivate || logical.State != LogicalKeyState.Active ||
            logical.ActiveVersion is not KeyVersion version)
        {
            throw new CryptographicException("Signing requires an Active private key.");
        }

        KeyReference reference = new(ProviderId, handle.KeyId, version);
        KeyVersionDescriptor exact = await RequireExactAsync(reference, WellKnownCapabilities.Sign, true,
            cancellationToken).ConfigureAwait(false);
        byte[] input = message.ToArray();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            byte[] output = await _keys.SignAsync(reference, exact.Algorithm, input, cancellationToken)
                .ConfigureAwait(false);
            if (output is null)
            {
                throw new CryptographicException("Signature executor produced no signature.");
            }
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SignaturePayload(reference, exact.Algorithm, output);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(output);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    /// <summary>False is reserved for an invalid signature; provider, policy and metadata failures throw.</summary>
    public ValueTask<bool> VerifySignatureAsync(SignaturePayload signature, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ValidateHandle(new LogicalKeyHandle(signature.Reference.ProviderId, signature.Reference.KeyId));
        CheckMessage(message.Length);
        cancellationToken.ThrowIfCancellationRequested();
        return WithMessageSnapshotAsync(message,
            captured => VerifyCoreAsync(signature, captured, cancellationToken));
    }

    private async ValueTask<bool> VerifyCoreAsync(SignaturePayload signature,
        ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        KeyVersionDescriptor exact = await RequireExactAsync(signature.Reference,
            WellKnownCapabilities.VerifySignature, false, cancellationToken).ConfigureAwait(false);
        if (exact.Algorithm != signature.Algorithm)
        {
            throw new CryptographicException("Signature algorithm differs from the exact key version.");
        }

        byte[] input = message.ToArray();
        byte[] bytes = signature.ExportSignatureCopy();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await _keys.VerifyAsync(signature.Reference, signature.Algorithm, input, bytes,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>Fixes the caller-owned input before asynchronous provider metadata checks.</summary>
    private static async ValueTask<T> WithMessageSnapshotAsync<T>(ReadOnlyMemory<byte> message,
        Func<byte[], ValueTask<T>> operation)
    {
        byte[] captured = message.ToArray();
        try
        {
            return await operation(captured).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(captured);
        }
    }

    private async ValueTask<KeyVersionDescriptor> RequireExactAsync(KeyReference reference,
        CapabilityId capability, bool newOperation, CancellationToken cancellationToken)
    {
        ProviderCapabilitySnapshot advertised = await _metadata.GetCapabilitiesAsync(cancellationToken)
            .ConfigureAwait(false);
        if (advertised is null || advertised.ProviderId != ProviderId || !advertised.Supports(capability))
        {
            throw new CryptographicException("Provider does not advertise the requested signature capability.");
        }

        KeyDescriptor owner = await _metadata.FindLogicalAsync(new LogicalKeyHandle(reference.ProviderId, reference.KeyId),
            cancellationToken).ConfigureAwait(false) ?? throw new CryptographicException("Logical signature key is unavailable.");
        if (owner.ProviderId != ProviderId || owner.KeyId != reference.KeyId ||
            (owner.Kind != KeyKind.AsymmetricPrivate && owner.Kind != KeyKind.AsymmetricPublic) ||
            (!newOperation && owner.State is not (LogicalKeyState.Active or LogicalKeyState.Retired)) ||
            (newOperation && (owner.Kind != KeyKind.AsymmetricPrivate || owner.State != LogicalKeyState.Active ||
                              owner.ActiveVersion != reference.Version)))
        {
            throw new CryptographicException("Signature key kind or logical state is not permitted.");
        }

        KeyVersionDescriptor result = await _metadata.FindExactAsync(new ExactKeyHandle(reference),
            cancellationToken).ConfigureAwait(false) ?? throw new CryptographicException("Version is unavailable.");
        if (result.Reference != reference || !result.Capabilities.Contains(capability) ||
            (newOperation && result.State != KeyVersionState.Active) ||
            (!newOperation && result.State is not (KeyVersionState.Active or KeyVersionState.Retired)))
        {
            throw new CryptographicException("Signature capability or key state is not permitted.");
        }

        AlgorithmPolicy.EnsureAllowed(result.Algorithm, AlgorithmPurpose.Signature,
            newOperation ? AlgorithmUse.NewOperation : AlgorithmUse.HistoricalVerification);
        return result;
    }

    private void ValidateHandle(LogicalKeyHandle handle)
    {
        if (!handle.IsDefined || handle.ProviderId != ProviderId)
        {
            throw new ArgumentException("The key belongs to another provider or is undefined.", nameof(handle));
        }
    }

    private static void CheckMessage(int length)
    {
        if (length is < 0 or > 16 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "Whole-buffer signing limit is 16 MiB.");
        }
    }
}
