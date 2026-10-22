using Android.App;
using Android.Content;
using AndroidX.Security.Crypto;
using Laveyana.Security.Abstractions.Identifiers;
using Microsoft.Maui.Storage;
using System.IO;
using System.Runtime.Versioning;

namespace Laveyana.Security.Maui.Android.Storage;

/// <summary>
/// Optional Android encrypted-preferences adapter that does not silently repair
/// corrupted storage or suppress errors surfaced by AndroidX Security Crypto.
/// </summary>
/// <remarks>
/// EXPERIMENTAL: this is not durable, rollback-protected or an IKeyStore.
/// The underlying AndroidX EncryptedSharedPreferences API is deprecated.
/// Its software Tink data-encryption keys and Android Keystore master-key
/// policy are NOT evidence of hardware-enforced storage on every device.
/// Reads return null only when AndroidX successfully reports no value; there
/// is no independent proof that an absent item was never previously stored.
/// Persisted values have no migration path from MAUI SecureStorage.Default.
/// Do not use for irreplaceable secrets or as a critical AES-GCM root.
/// </remarks>
[SupportedOSPlatform("android31.0")]
public sealed class AndroidFailClosedSecureStorage : ISecureStorage
{
    private const string PreferencesSuffix = ".laveyana.security.strict-prefs.v1.";
    private const string MasterAliasPrefix = "laveyana.security.strict-master.v1.";
    private readonly Context _context;
    private readonly string _preferencesName;
    private readonly string _masterAlias;

    /// <summary>Uses an explicit, stable application/provider identity and isolated preferences.</summary>
    public AndroidFailClosedSecureStorage(ProviderId providerId, Context context)
    {
        if (!OperatingSystem.IsAndroidVersionAtLeast(31))
        {
            throw new PlatformNotSupportedException("Android API 31 or later is required.");
        }

        if (!providerId.IsDefined)
        {
            throw new ArgumentException("Provider ID must remain stable between launches.", nameof(providerId));
        }

        ArgumentNullException.ThrowIfNull(context);
        _context = context.ApplicationContext ?? context;
        string id = providerId.Value.ToString("N");
        _preferencesName = (_context.PackageName ??
            throw new InvalidOperationException("Android package identity is unavailable.")) +
            PreferencesSuffix + id;
        _masterAlias = MasterAliasPrefix + id;
    }

    /// <summary>
    /// Opens and decrypts one value. Security/corruption failures propagate;
    /// no hidden preference reset, retry, or RemoveAll is performed.
    /// </summary>
    public Task<string?> GetAsync(string key)
    {
        ValidateKey(key);
        return Task.Run(() =>
        {
            using ISharedPreferences prefs = OpenEncryptedPreferences();
            return prefs.GetString(key, null);
        });
    }

    /// <summary>
    /// Encrypts and commits synchronously inside a worker. False Commit means failure,
    /// not a successful write; actual persistence after power loss is not promised.
    /// </summary>
    public Task SetAsync(string key, string value)
    {
        ValidateKey(key);
        ArgumentNullException.ThrowIfNull(value);
        return Task.Run(() =>
        {
            using ISharedPreferences prefs = OpenEncryptedPreferences();
            using ISharedPreferencesEditor editor = prefs.Edit() ??
                throw new IOException("Cannot open encrypted preferences editor.");
            editor.PutString(key, value);
            if (!editor.Commit())
            {
                throw new IOException("Encrypted preferences write commit was not confirmed.");
            }
        });
    }

    /// <summary>
    /// Removes the exact key with synchronous Commit. A write failure throws;
    /// a missing key is idempotently considered deleted.
    /// </summary>
    public bool Remove(string key)
    {
        ValidateKey(key);
        using ISharedPreferences prefs = OpenEncryptedPreferences();
        using ISharedPreferencesEditor editor = prefs.Edit() ??
            throw new IOException("Cannot open encrypted preferences editor.");
        editor.Remove(key);
        if (!editor.Commit())
        {
            throw new IOException("Encrypted preferences delete commit was not confirmed.");
        }

        return true;
    }

    /// <summary>Broad destructive deletion is intentionally unavailable.</summary>
    public void RemoveAll() =>
        throw new NotSupportedException("Bulk deletion is intentionally unsupported; delete exact keys.");

    private ISharedPreferences OpenEncryptedPreferences()
    {
        // AndroidX's encryption primitive is used as-is: we do not implement
        // our own AEAD or reset/recover a broken keyset. Keep every exception.
#pragma warning disable CS0618 // AndroidX EncryptedSharedPreferences API is deprecated.
        using MasterKey.Builder builder = new(_context, _masterAlias);
        MasterKey.Builder configured = builder.SetKeyScheme(MasterKey.KeyScheme.Aes256Gcm)
            ?? throw new IOException("Android master key scheme configuration failed.");
        using MasterKey master = configured.Build()
            ?? throw new IOException("Android Keystore master key is unavailable.");
        return EncryptedSharedPreferences.Create(_context, _preferencesName, master,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.Aes256Siv,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.Aes256Gcm)
            ?? throw new IOException("Android encrypted preferences initialization failed.");
#pragma warning restore CS0618
    }

    private static void ValidateKey(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (key.Length > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(key), "Storage key exceeds the supported length.");
        }
    }
}
