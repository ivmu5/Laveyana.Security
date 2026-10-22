using System.Runtime.Versioning;
using System.Security.Cryptography;
using Android.Security.Keystore;
using Java.Security;
using Java.Security.Spec;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Maui.NativeKeys;

namespace Laveyana.Security.Maui.Android;

/// <summary>
/// Android 12+ hardware-backed AndroidKeyStore ECDSA P-256 signing.
/// Does not silently accept software-backed key material.
/// </summary>
/// <remarks>
/// Android Keystore aliases have no cross-process CAS; key creation races are not
/// prevented. This is not a versioned key provider, hardware attestation, secure
/// deletion, biometric/user-presence enforcement, or recovery/rollback authority.
/// </remarks>
[SupportedOSPlatform("android31.0")]
public sealed class AndroidKeystoreSigningKeyService : INativeSigningKeyService
{
    private const string ProviderName = "AndroidKeyStore";
    private const string AliasPrefix = "laveyana.security.maui.android.p256.v1.";
    private const int MaximumMessageLength = 1024 * 1024;

    /// <summary>Constructs a signer for an app-persisted provider identity.</summary>
    public AndroidKeystoreSigningKeyService(ProviderId providerId)
    {
        if (!OperatingSystem.IsAndroidVersionAtLeast(31))
        {
            throw new PlatformNotSupportedException("Hardware-policy verification requires Android API 31 or higher.");
        }

        if (!providerId.IsDefined)
        {
            throw new ArgumentException("Provider identity must be defined.", nameof(providerId));
        }

        ProviderId = providerId;
    }

    /// <inheritdoc/>
    public ProviderId ProviderId { get; }

    /// <inheritdoc/>
    public ValueTask<NativeSigningKeyInfo> CreateAsync(KeyId keyId,
        CancellationToken cancellationToken = default)
    {
        string alias = Alias(keyId);
        cancellationToken.ThrowIfCancellationRequested();

        using Java.Security.KeyStore store = OpenStore();
        if (store.ContainsAlias(alias))
        {
            throw new InvalidOperationException("Key ID is already in use.");
        }

        using KeyGenParameterSpec.Builder builder = new(alias, KeyStorePurpose.Sign);
        using ECGenParameterSpec curve = new("secp256r1");
        builder.SetAlgorithmParameterSpec(curve);
        builder.SetDigests("SHA-256");
        using KeyGenParameterSpec spec = builder.Build();
        using KeyPairGenerator generator = KeyPairGenerator.GetInstance("EC", ProviderName)
            ?? throw new CryptographicException("AndroidKeyStore key generator unavailable.");
        generator.Initialize(spec);

        // An AndroidKeyStore entry may remain if a later validation fails.
        // Never silently fall back to a software-generated signing key.
        using KeyPair pair = generator.GenerateKeyPair()
            ?? throw new CryptographicException("Keystore did not generate a key pair.");
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(ReadVerifiedInfo(store, alias, keyId));
    }

    /// <inheritdoc/>
    public ValueTask<NativeSigningKeyInfo?> FindAsync(KeyId keyId,
        CancellationToken cancellationToken = default)
    {
        string alias = Alias(keyId);
        cancellationToken.ThrowIfCancellationRequested();
        using Java.Security.KeyStore store = OpenStore();
        if (!store.ContainsAlias(alias))
        {
            return ValueTask.FromResult<NativeSigningKeyInfo?>(null);
        }

        return ValueTask.FromResult<NativeSigningKeyInfo?>(ReadVerifiedInfo(store, alias, keyId));
    }

    /// <inheritdoc/>
    public ValueTask<byte[]> SignAsync(KeyId keyId, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default)
    {
        string alias = Alias(keyId);
        if (message.Length > MaximumMessageLength)
        {
            throw new ArgumentOutOfRangeException(nameof(message));
        }

        cancellationToken.ThrowIfCancellationRequested();
        using Java.Security.KeyStore store = OpenStore();
        IPrivateKey privateKey = RequireHardwareKey(store, alias);
        using Signature signer = Signature.GetInstance("SHA256withECDSA")
            ?? throw new CryptographicException("SHA256withECDSA unavailable.");
        signer.InitSign(privateKey);
        signer.Update(message.ToArray());
        cancellationToken.ThrowIfCancellationRequested();
        byte[] der = signer.Sign() ?? throw new CryptographicException("No signature returned.");
        return ValueTask.FromResult(EcdsaDerSignatureCodec.ToP1363(der));
    }

    /// <inheritdoc/>
    public ValueTask DeleteAsync(KeyId keyId, CancellationToken cancellationToken = default)
    {
        string alias = Alias(keyId);
        cancellationToken.ThrowIfCancellationRequested();
        using Java.Security.KeyStore store = OpenStore();
        if (!store.ContainsAlias(alias))
        {
            throw new KeyNotFoundException("Signing key does not exist.");
        }

        store.DeleteEntry(alias);
        return ValueTask.CompletedTask;
    }

    private static Java.Security.KeyStore OpenStore()
    {
        Java.Security.KeyStore store = Java.Security.KeyStore.GetInstance(ProviderName)
            ?? throw new CryptographicException("AndroidKeyStore unavailable.");
        try
        {
            store.Load(null, null);
            return store;
        }
        catch
        {
            store.Dispose();
            throw;
        }
    }

    private static IPrivateKey RequireHardwareKey(Java.Security.KeyStore store, string alias)
    {
        IPrivateKey privateKey = store.GetKey(alias, null) as IPrivateKey
            ?? throw new KeyNotFoundException("Signing key does not exist.");
        using KeyFactory factory = KeyFactory.GetInstance("EC", ProviderName)
            ?? throw new CryptographicException("AndroidKeyStore key factory unavailable.");
        using KeyInfo info = factory.GetKeySpec(privateKey,
            Java.Lang.Class.FromType(typeof(KeyInfo))) as KeyInfo
            ?? throw new CryptographicException("AndroidKeyStore key security level unavailable.");

        int level = info.SecurityLevel;
        if (level != (int)KeyStoreSecurityLevel.TrustedEnvironment &&
            level != (int)KeyStoreSecurityLevel.Strongbox)
        {
            throw new CryptographicException("Signing key is not verified as TEE/StrongBox backed.");
        }

        return privateKey;
    }

    private NativeSigningKeyInfo ReadVerifiedInfo(Java.Security.KeyStore store,
        string alias, KeyId keyId)
    {
        _ = RequireHardwareKey(store, alias);
        byte[] spki = store.GetCertificate(alias)?.PublicKey?.GetEncoded()
            ?? throw new CryptographicException("Signing public key is unavailable.");
        return new NativeSigningKeyInfo(ProviderId, keyId, spki);
    }

    private string Alias(KeyId keyId)
    {
        if (!keyId.IsDefined)
        {
            throw new ArgumentException("A defined key ID is required.", nameof(keyId));
        }

        return AliasPrefix + ProviderId.Value.ToString("N") + "." + keyId.Value.ToString("N");
    }
}
