using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Maui.NativeKeys;

/// <summary>
/// Low-level device-local ECDSA P-256 signing primitive. Private material must not be
/// exported. This is NOT a versioned IKeyProviderBackend.
/// </summary>
/// <remarks>
/// Implementations must explicitly document hardware guarantees and must not silently
/// fall back from required hardware-backed keys to software storage. Callers must
/// persist IDs and never reuse one after deletion. Failures around creation and
/// deletion can have uncertain persistent outcomes: reconcile with FindAsync.
/// There is no atomic cross-process CreateIfAbsent or key version lifecycle.
/// Callers must authenticate purpose/protocol/version by domain-separating all
/// signed messages; this low-level API signs the exact supplied bytes.
/// </remarks>
public interface INativeSigningKeyService
{
    /// <summary>Stable persistent namespace for application-owned keys.</summary>
    ProviderId ProviderId { get; }

    /// <summary>Creates a non-exportable signing key under a previously unused ID.</summary>
    ValueTask<NativeSigningKeyInfo> CreateAsync(KeyId keyId, CancellationToken cancellationToken = default);

    /// <summary>Reads the public key and owning ProviderId for an exact ID, or null when absent.</summary>
    ValueTask<NativeSigningKeyInfo?> FindAsync(KeyId keyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs using ECDSA P-256/SHA-256. Returns a 64-byte IEEE P1363 (r || s)
    /// signature, not ASN.1 DER. There is no automatic domain separation;
    /// different protocols MUST use distinct unambiguous message encodings.
    /// </summary>
    ValueTask<byte[]> SignAsync(KeyId keyId, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default);

    /// <summary>Deletes the exact key without promising secure physical erasure.</summary>
    ValueTask DeleteAsync(KeyId keyId, CancellationToken cancellationToken = default);
}
