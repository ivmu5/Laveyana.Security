using System.Runtime.Versioning;
using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Maui.NativeKeys;

/// <summary>
/// Windows-only TPM-backed ECDSA P-256 signing with Microsoft Platform Crypto Provider.
/// Never falls back to the Microsoft Software Key Storage Provider.
/// </summary>
/// <remarks>
/// Requires a compatible Windows TPM and permitted key-store access. This experimental
/// service does not implement key versions, attestation, user-presence policy,
/// cross-process CAS, secure deletion, or rollback protection.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsTpmSigningKeyService : INativeSigningKeyService
{
    private const string KeyPrefix = "Laveyana.Security.Maui.Tpm.P256.v1.";
    private const int MaximumMessageLength = 1024 * 1024;

    /// <summary>Constructs a signer for an application-persisted provider identity.</summary>
    public WindowsTpmSigningKeyService(ProviderId providerId)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows TPM signing requires Windows.");
        }

        if (!providerId.IsDefined)
        {
            throw new ArgumentException("Provider identity must be persistent and defined.", nameof(providerId));
        }

        ProviderId = providerId;
    }

    /// <inheritdoc />
    public ProviderId ProviderId { get; }

    /// <inheritdoc />
    public ValueTask<NativeSigningKeyInfo> CreateAsync(KeyId keyId,
        CancellationToken cancellationToken = default)
    {
        string name = GetKeyName(keyId);
        cancellationToken.ThrowIfCancellationRequested();

        // A duplicate named key must fail; overwriting keys is prohibited.
        CngKeyCreationParameters parameters = new()
        {
            Provider = CngProvider.MicrosoftPlatformCryptoProvider,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing,
            KeyCreationOptions = CngKeyCreationOptions.None
        };

        using CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, name, parameters);
        using ECDsaCng signer = new(key);
        return ValueTask.FromResult(new NativeSigningKeyInfo(keyId, signer.ExportSubjectPublicKeyInfo()));
    }

    /// <inheritdoc />
    public ValueTask<NativeSigningKeyInfo?> FindAsync(KeyId keyId,
        CancellationToken cancellationToken = default)
    {
        string name = GetKeyName(keyId);
        cancellationToken.ThrowIfCancellationRequested();
        if (!CngKey.Exists(name, CngProvider.MicrosoftPlatformCryptoProvider))
        {
            return ValueTask.FromResult<NativeSigningKeyInfo?>(null);
        }

        using CngKey key = OpenRequired(name);
        using ECDsaCng signer = new(key);
        return ValueTask.FromResult<NativeSigningKeyInfo?>(
            new NativeSigningKeyInfo(keyId, signer.ExportSubjectPublicKeyInfo()));
    }

    /// <inheritdoc />
    public ValueTask<byte[]> SignAsync(KeyId keyId, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default)
    {
        string name = GetKeyName(keyId);
        if (message.Length > MaximumMessageLength)
        {
            throw new ArgumentOutOfRangeException(nameof(message), "Message exceeds the signing limit.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        using CngKey key = OpenRequired(name);
        using ECDsaCng signer = new(key);
        byte[] signature = signer.SignData(message.Span, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (signature.Length != 64)
        {
            throw new CryptographicException("Unexpected signature format from TPM signer.");
        }

        return ValueTask.FromResult(signature);
    }

    /// <inheritdoc />
    public ValueTask DeleteAsync(KeyId keyId, CancellationToken cancellationToken = default)
    {
        string name = GetKeyName(keyId);
        cancellationToken.ThrowIfCancellationRequested();
        using CngKey key = OpenRequired(name);
        key.Delete();
        return ValueTask.CompletedTask;
    }

    private string GetKeyName(KeyId keyId)
    {
        if (!keyId.IsDefined)
        {
            throw new ArgumentException("Key ID must be defined.", nameof(keyId));
        }

        return KeyPrefix + ProviderId.Value.ToString("N") + "." + keyId.Value.ToString("N");
    }

    private static CngKey OpenRequired(string name)
    {
        CngKey key = CngKey.Open(name, CngProvider.MicrosoftPlatformCryptoProvider);
        if (!string.Equals(key.Algorithm.Algorithm, CngAlgorithm.ECDsaP256.Algorithm, StringComparison.Ordinal))
        {
            key.Dispose();
            throw new CryptographicException("Stored key has an unexpected algorithm.");
        }

        return key;
    }
}
