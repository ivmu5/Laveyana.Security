using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Payloads;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Abstractions.Streaming;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>Typed convenience operations; providers remain responsible for operation-time authorization.</summary>
public static class ManagedKeyOperationExtensions
{
    /// <summary>Computes an HMAC on the current Active version of this typed symmetric key.</summary>
    public static ValueTask<MacResult> ComputeMacAsync(this MacKey key, IManagedMacBackend backend,
        ReadOnlyMemory<byte> message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(backend);
        RequireSameProvider(key.Handle.ProviderId, backend.ProviderId);
        return backend.ComputeMacAsync(key.Handle, message, cancellationToken);
    }

    /// <summary>Verifies a historical full HMAC tag of this logical key without changing version.</summary>
    public static ValueTask<bool> VerifyMacAsync(this MacKey key, IManagedMacBackend backend,
        MacResult result, ReadOnlyMemory<byte> message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(backend);
        ArgumentNullException.ThrowIfNull(result);
        RequireExactLogical(key.Handle, result.Reference, backend.ProviderId);
        return backend.VerifyMacAsync(result, message, cancellationToken);
    }

    /// <summary>Computes an HMAC over a stream, retaining the typed key identity.</summary>
    public static Task<MacResult> ComputeMacStreamAsync(this MacKey key, IStreamingMacBackend backend,
        Stream message, StreamProcessingOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(backend);
        RequireSameProvider(key.Handle.ProviderId, backend.ProviderId);
        return backend.ComputeMacStreamAsync(key.Handle, message, options, cancellationToken);
    }

    /// <summary>Verifies a streamed HMAC against its exact historical key version.</summary>
    public static Task<bool> VerifyMacStreamAsync(this MacKey key, IStreamingMacBackend backend,
        MacResult result, Stream message, StreamProcessingOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(backend);
        ArgumentNullException.ThrowIfNull(result);
        RequireExactLogical(key.Handle, result.Reference, backend.ProviderId);
        return backend.VerifyMacStreamAsync(result, message, options, cancellationToken);
    }

    /// <summary>Signs using the current Active private version, not a cached version.</summary>
    public static ValueTask<SignaturePayload> SignAsync(this AsymmetricPrivateKey key,
        IManagedSignatureBackend backend, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(backend);
        RequireSameProvider(key.Handle.ProviderId, backend.ProviderId);
        return backend.SignAsync(key.Handle, message, cancellationToken);
    }

    /// <summary>Verifies a payload against this public-only logical identity and its exact version.</summary>
    public static ValueTask<bool> VerifySignatureAsync(this AsymmetricPublicKey key,
        IManagedSignatureBackend backend, SignaturePayload payload, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(backend);
        ArgumentNullException.ThrowIfNull(payload);
        RequireExactLogical(key.Handle, payload.Reference, backend.ProviderId);
        return backend.VerifySignatureAsync(payload, message, cancellationToken);
    }

    /// <summary>Agrees on a P-256 shared secret internally, derives via HKDF and returns an ephemeral lease.</summary>
    public static ValueTask<DerivedKeyLease> AgreeAsync(this AsymmetricPrivateKey key,
        IManagedKeyAgreementBackend backend, ReadOnlyMemory<byte> peerPublicKeySpki,
        DerivationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(backend);
        RequireSameProvider(key.Handle.ProviderId, backend.ProviderId);
        return backend.AgreeAsync(key.Handle, peerPublicKeySpki, context, cancellationToken);
    }

    /// <summary>Derives a disposable HKDF result under the provider-owned Active symmetric version.</summary>
    public static ValueTask<DerivedKeyLease> DeriveAsync(this DerivationKey key,
        IManagedDerivationBackend backend, DerivationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(backend);
        RequireSameProvider(key.Handle.ProviderId, backend.ProviderId);
        return backend.DeriveAsync(key.Handle, context, cancellationToken);
    }

    private static void RequireSameProvider(ProviderId expected, ProviderId actual)
    {
        if (expected != actual)
        {
            throw new ArgumentException("The typed key belongs to a different provider.");
        }
    }

    private static void RequireExactLogical(LogicalKeyHandle logical, KeyReference exact, ProviderId provider)
    {
        if (!logical.IsDefined || !exact.IsDefined || logical.ProviderId != provider ||
            logical.ProviderId != exact.ProviderId || logical.KeyId != exact.KeyId)
        {
            throw new ArgumentException("Result belongs to a different logical key or provider.");
        }
    }
}
