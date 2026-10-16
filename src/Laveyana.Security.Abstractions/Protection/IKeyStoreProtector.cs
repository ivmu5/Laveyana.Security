using Laveyana.Security.Abstractions.Sensitive;

namespace Laveyana.Security.Abstractions.Protection;

/// <summary>Pluggable authenticated at-rest protection boundary independent of file storage.</summary>
/// <remarks>
/// An implementation owns its root secret internally, never returns it, and must authenticate
/// purpose, stable protector reference and supplied associated context. Decryption MUST fail
/// closed for wrong context, purpose, tampered data, unsupported generation or corruption.
/// The caller owns and disposes plaintext leases, including on failure; returned plaintext
/// leases belong to the caller. Protectors must not retain borrowed plaintext bytes.
/// Cancellation is not evidence that a separately committed store write was rolled back.
/// </remarks>
public interface IKeyStoreProtector
{
    /// <summary>Gets the stable reference used for newly protected envelopes.</summary>
    ProtectorReference CurrentReference { get; }

    /// <summary>Protects caller-owned plaintext for a distinct purpose and exact authenticated context.</summary>
    ValueTask<ProtectedStoreEnvelope> ProtectAsync(
        SensitiveMaterialLease plaintext,
        ProtectionPurpose purpose,
        ReadOnlyMemory<byte> authenticatedContext,
        CancellationToken cancellationToken = default);

    /// <summary>Authenticates and decrypts an envelope into a newly owned sensitive lease.</summary>
    /// <remarks>Implementations may read historical protector generations without changing CurrentReference.</remarks>
    ValueTask<SensitiveMaterialLease> UnprotectAsync(
        ProtectedStoreEnvelope envelope,
        ProtectionPurpose expectedPurpose,
        ReadOnlyMemory<byte> authenticatedContext,
        CancellationToken cancellationToken = default);
}
