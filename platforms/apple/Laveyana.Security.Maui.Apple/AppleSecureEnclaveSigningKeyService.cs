using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Foundation;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Maui.NativeKeys;
using Security;

namespace Laveyana.Security.Maui.Apple;

/// <summary>
/// Device-bound Secure Enclave ECDSA P-256 signatures on supported iOS and
/// Mac Catalyst hardware. Private material is never exported.
/// </summary>
/// <remarks>
/// Uses ThisDeviceOnly/WhenUnlocked and PrivateKeyUsage without implicit
/// biometrics. Keychain alias creation is not atomic across processes. A
/// crash can leave a persistent key with an unknown outcome. The interface
/// supplies no versioned lifecycle, hardware attestation, rollback protection,
/// user-presence requirement, or evidence of secure physical deletion.
/// </remarks>
[SupportedOSPlatform("ios13.0")]
[SupportedOSPlatform("maccatalyst15.0")]
public sealed class AppleSecureEnclaveSigningKeyService : INativeSigningKeyService
{
    private const string TagPrefix = "laveyana.security.maui.enclave.p256.v1.";
    private const int MaximumMessageLength = 1024 * 1024;

    /// <summary>Uses a persistent, app-owned provider identity.</summary>
    public AppleSecureEnclaveSigningKeyService(ProviderId providerId)
    {
        if (!OperatingSystem.IsIOS() && !OperatingSystem.IsMacCatalyst())
        {
            throw new PlatformNotSupportedException("Apple Secure Enclave requires iOS or Mac Catalyst.");
        }

        if (!providerId.IsDefined)
        {
            throw new ArgumentException("A stable provider ID is required.", nameof(providerId));
        }

        ProviderId = providerId;
    }

    /// <inheritdoc/>
    public ProviderId ProviderId { get; }

    /// <inheritdoc/>
    public ValueTask<NativeSigningKeyInfo> CreateAsync(KeyId keyId,
        CancellationToken cancellationToken = default)
    {
        string tagText = Tag(keyId);
        cancellationToken.ThrowIfCancellationRequested();
        using NSData tag = NSData.FromArray(Encoding.UTF8.GetBytes(tagText));
        using SecKey? existing = OpenKey(tag);
        if (existing is not null)
        {
            throw new InvalidOperationException("The key ID is already in use.");
        }

        using SecAccessControl control = new(SecAccessible.WhenUnlockedThisDeviceOnly,
            SecAccessControlCreateFlags.PrivateKeyUsage);
        SecKeyParameters privateAttrs = new()
        {
            IsPermanent = true,
            ApplicationTag = tag,
            AccessControl = control,
            CanSign = true,
        };
        SecKeyGenerationParameters parameters = new()
        {
            KeyType = SecKeyType.ECSecPrimeRandom,
            KeySizeInBits = 256,
            TokenID = SecTokenID.SecureEnclave,
            PrivateKeyAttrs = privateAttrs,
        };

        // kSecAttrTokenIDSecureEnclave is mandatory. A software fallback is
        // not offered if the hardware token is unavailable.
        using SecKey privateKey = SecKey.CreateRandomKey(parameters, out NSError? _)
            ?? throw new CryptographicException("Secure Enclave key generation failed.");
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(PublicInfo(privateKey, keyId));
    }

    /// <inheritdoc/>
    public ValueTask<NativeSigningKeyInfo?> FindAsync(KeyId keyId,
        CancellationToken cancellationToken = default)
    {
        string name = Tag(keyId);
        cancellationToken.ThrowIfCancellationRequested();
        using NSData tag = NSData.FromArray(Encoding.UTF8.GetBytes(name));
        using SecKey? key = OpenKey(tag);
        return ValueTask.FromResult(key is null ? null : PublicInfo(key, keyId));
    }

    /// <inheritdoc/>
    public ValueTask<byte[]> SignAsync(KeyId keyId, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default)
    {
        string name = Tag(keyId);
        if (message.Length > MaximumMessageLength)
        {
            throw new ArgumentOutOfRangeException(nameof(message), "Message is too large.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        using NSData tag = NSData.FromArray(Encoding.UTF8.GetBytes(name));
        using SecKey key = OpenKey(tag) ?? throw new KeyNotFoundException("Signing key not found.");
        if (!key.IsAlgorithmSupported(SecKeyOperationType.Sign, SecKeyAlgorithm.EcdsaSignatureMessageX962Sha256))
        {
            throw new CryptographicException("Secure Enclave signing algorithm unavailable.");
        }

        using NSData input = NSData.FromArray(message.ToArray());
        using NSData der = key.CreateSignature(SecKeyAlgorithm.EcdsaSignatureMessageX962Sha256,
            input, out NSError? _) ?? throw new CryptographicException("Secure Enclave signing failed.");
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(EcdsaDerSignatureCodec.ToP1363(der.ToArray()));
    }

    /// <inheritdoc/>
    public ValueTask DeleteAsync(KeyId keyId, CancellationToken cancellationToken = default)
    {
        string name = Tag(keyId);
        cancellationToken.ThrowIfCancellationRequested();
        using NSData tag = NSData.FromArray(Encoding.UTF8.GetBytes(name));
        using SecRecord query = MakeQuery(tag);
        SecStatusCode status = SecKeyChain.Remove(query);
        if (status == SecStatusCode.ItemNotFound)
        {
            throw new KeyNotFoundException("Signing key not found.");
        }

        if (status != SecStatusCode.Success)
        {
            throw new CryptographicException("Keychain delete failed.");
        }

        return ValueTask.CompletedTask;
    }

    private static SecKey? OpenKey(NSData tag)
    {
        using SecRecord query = MakeQuery(tag);
        object? found = SecKeyChain.QueryAsConcreteType(query, out SecStatusCode status);
        if (status == SecStatusCode.ItemNotFound)
        {
            return null;
        }

        if (status != SecStatusCode.Success || found is not SecKey key)
        {
            (found as IDisposable)?.Dispose();
            throw new CryptographicException("Secure Enclave key lookup failed.");
        }

        return key;
    }

    private static SecRecord MakeQuery(NSData tag) => new(SecKind.Key)
    {
        ApplicationTag = tag,
        KeyClass = SecKeyClass.Private,
        TokenID = SecTokenID.SecureEnclave
    };

    private static NativeSigningKeyInfo PublicInfo(SecKey privateKey, KeyId keyId)
    {
        using SecKey publicKey = privateKey.GetPublicKey()
            ?? throw new CryptographicException("Secure Enclave public key unavailable.");
        using NSData representation = publicKey.GetExternalRepresentation(out NSError? _)
            ?? throw new CryptographicException("Secure Enclave public point unavailable.");
        return new NativeSigningKeyInfo(keyId,
            AppleP256PublicKeyCodec.ToSubjectPublicKeyInfo(representation.ToArray()));
    }

    private string Tag(KeyId keyId)
    {
        if (!keyId.IsDefined)
        {
            throw new ArgumentException("A defined key ID is required.", nameof(keyId));
        }

        return TagPrefix + ProviderId.Value.ToString("N") + "." + keyId.Value.ToString("N");
    }
}
