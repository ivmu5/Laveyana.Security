using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Payloads;

namespace Laveyana.Security.Abstractions.Providers;

/// <summary>
/// Optional, provider-owned authenticated encryption execution boundary.
/// A provider enforces current state, key capability and actual material access at operation time.
/// </summary>
public interface IAuthenticatedEncryptionBackend : IKeyProviderBackend
{
    /// <summary>Encrypts using the current Active version, recording the exact used key reference.</summary>
    ValueTask<EncryptedPayload> EncryptAsync(LogicalKeyHandle handle, ReadOnlyMemory<byte> plaintext,
        ReadOnlyMemory<byte> applicationAad = default, CancellationToken cancellationToken = default);

    /// <summary>Authenticates and decrypts using the exact version embedded in the payload.</summary>
    ValueTask<byte[]> DecryptAsync(EncryptedPayload payload, ReadOnlyMemory<byte> applicationAad = default,
        CancellationToken cancellationToken = default);

    /// <summary>Returns null only when the authentication tag fails; other failures propagate.</summary>
    ValueTask<byte[]?> TryDecryptAsync(EncryptedPayload payload, ReadOnlyMemory<byte> applicationAad = default,
        CancellationToken cancellationToken = default);

    /// <summary>Encrypts with separated ciphertext and typed authenticated metadata.</summary>
    ValueTask<(DetachedEncryptedPayload Metadata, byte[] Ciphertext)> EncryptDetachedAsync(
        LogicalKeyHandle handle, ReadOnlyMemory<byte> plaintext, ReadOnlyMemory<byte> applicationAad = default,
        CancellationToken cancellationToken = default);

    /// <summary>Authenticates a separately transported ciphertext and exact key metadata.</summary>
    ValueTask<byte[]> DecryptDetachedAsync(DetachedEncryptedPayload metadata, ReadOnlyMemory<byte> ciphertext,
        ReadOnlyMemory<byte> applicationAad = default, CancellationToken cancellationToken = default);

    /// <summary>Returns null only for detached ciphertext authentication failure.</summary>
    ValueTask<byte[]?> TryDecryptDetachedAsync(DetachedEncryptedPayload metadata, ReadOnlyMemory<byte> ciphertext,
        ReadOnlyMemory<byte> applicationAad = default, CancellationToken cancellationToken = default);
}
