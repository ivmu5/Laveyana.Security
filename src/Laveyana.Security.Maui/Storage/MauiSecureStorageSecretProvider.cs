using System.IO;
using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Secrets;
using Laveyana.Security.Abstractions.Sensitive;
using Microsoft.Maui.Storage;

namespace Laveyana.Security.Maui.Storage;

/// <summary>
/// App-scoped, best-effort secret management backed by MAUI ISecureStorage.
/// An immediate readback checks writes, but cannot guarantee future persistence.
/// </summary>
/// <remarks>
/// This is NOT an IKeyStore: MAUI ISecureStorage does not provide durable atomic CAS,
/// cross-process transactions, a monotonic rollback authority, or power-loss guarantees.
/// All code able to resolve this provider is trusted; it does not implement end-user
/// authorization. Use only for small, recoverable app secrets, not master keys requiring
/// durable lifecycle guarantees. The adapter never calls RemoveAll, but
/// underlying Android MAUI SecureStorage can clear shared preferences or
/// suppress errors and return null. Absence is not evidence that a key was
/// never created; never automatically recreate irreplaceable roots from null.
/// </remarks>
public sealed class MauiSecureStorageSecretProvider : ISecretManagementProvider
{
    private const string StorageNamePrefix = "laveyana.security.maui.v1.";
    private const string RecordPrefix = "LSM1:";

    /// <summary>
    /// Conservative upper bound for a secret, leaving room for Base64 encoding,
    /// authenticated identity and platform overhead under Windows' value-size limit.
    /// </summary>
    public const int MaximumSecretLength = 2048;

    private readonly ISecureStorage _storage;

    /// <summary>Constructs a provider with an app-owned stable identity.</summary>
    public MauiSecureStorageSecretProvider(ProviderId providerId, ISecureStorage storage)
    {
        if (!providerId.IsDefined)
        {
            throw new ArgumentException("A defined, stable provider ID is required.", nameof(providerId));
        }

        ProviderId = providerId;
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
    }

    /// <summary>Stable identity; persist or configure this value, never generate it on each launch.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>
    /// Returns metadata only for a readable, correctly bound record. Metadata is not authorization.
    /// </summary>
    public async ValueTask<SecretDescriptor?> FindAsync(
        SecretReference reference, CancellationToken cancellationToken = default)
    {
        using SecretReadResult? result = await GetAsync(reference, cancellationToken).ConfigureAwait(false);
        return result is null ? null : new SecretDescriptor(reference, canOpenMaterial: true);
    }

    /// <summary>
    /// Reads and validates one exact provider/secret identity into an owned, disposable lease.
    /// Malformed records and surfaced platform errors fail closed. Platform errors
    /// hidden by SecureStorage may appear as null and cannot be distinguished
    /// from genuine absence by this adapter.
    /// </summary>
    public async ValueTask<SecretReadResult?> GetAsync(
        SecretReference reference, CancellationToken cancellationToken = default)
    {
        string key = GetStorageKey(reference);
        cancellationToken.ThrowIfCancellationRequested();

        // MAUI does not accept CancellationToken; cancellation is only checked before I/O.
        string? value = await _storage.GetAsync(key).ConfigureAwait(false);
        if (value is null)
        {
            return null;
        }

        string expectedPrefix = RecordPrefix + reference + ":";
        if (!value.StartsWith(expectedPrefix, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Secure storage record version or identity mismatch.");
        }

        string encoded = value[expectedPrefix.Length..];
        if (encoded.Length is < 4 or > ((MaximumSecretLength + 2) / 3) * 4)
        {
            throw new InvalidDataException("Secure storage record is empty or exceeds the supported limit.");
        }

        byte[] material;
        try
        {
            material = Convert.FromBase64String(encoded);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("Secure storage record encoding is invalid.", exception);
        }

        try
        {
            if (material.Length is < 1 or > MaximumSecretLength ||
                !string.Equals(Convert.ToBase64String(material), encoded, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Secure storage record has invalid or non-canonical material.");
            }

            SensitiveMaterialLease lease = SensitiveMaterialLease.TakeOwnership(material);
            try
            {
                return new SecretReadResult(reference, lease);
            }
            catch
            {
                lease.Dispose();
                throw;
            }
        }
        catch
        {
            CryptographicOperations.ZeroMemory(material);
            throw;
        }
    }

    /// <summary>
    /// Sets or replaces a secret by stable identity. No CAS or durable commit is promised;
    /// an exception near the platform write may leave the outcome unknown.
    /// A matching immediate readback is required, not proof of durability.
    /// </summary>
    public async ValueTask SetAsync(
        SecretReference reference, SensitiveMaterialLease material,
        CancellationToken cancellationToken = default)
    {
        string key = GetStorageKey(reference);
        ArgumentNullException.ThrowIfNull(material);
        cancellationToken.ThrowIfCancellationRequested();

        string? value = null;
        string recordPrefix = RecordPrefix + reference + ":";
        material.UseMaterial(bytes =>
        {
            if (bytes.Length is < 1 or > MaximumSecretLength)
            {
                throw new ArgumentOutOfRangeException(nameof(material), "The secret is too large for this adapter.");
            }

            // MAUI accepts only strings. Intermediate immutable strings cannot be zeroized.
            value = recordPrefix + Convert.ToBase64String(bytes);
        });

        cancellationToken.ThrowIfCancellationRequested();
        await _storage.SetAsync(key, value!).ConfigureAwait(false);

        // MAUI Android may swallow initialization errors and silently skip a
        // write. Reject a missing or mismatched immediate readback. Do not
        // attempt cleanup: a platform write may already have committed.
        string? observed = await _storage.GetAsync(key).ConfigureAwait(false);
        if (!string.Equals(value, observed, StringComparison.Ordinal))
        {
            throw new IOException("SecureStorage write could not be verified by immediate readback.");
        }
    }

    /// <summary>
    /// Requests removal of this provider's exact key; the underlying platform
    /// may perform broader recovery cleanup outside the adapter's control.
    /// Missing values are treated as already deleted. Surfaced platform errors
    /// propagate, but the underlying Android recovery can silently clear other
    /// entries; this adapter cannot promise independent durable deletion.
    /// </summary>
    public ValueTask DeleteAsync(SecretReference reference, CancellationToken cancellationToken = default)
    {
        string key = GetStorageKey(reference);
        cancellationToken.ThrowIfCancellationRequested();
        _storage.Remove(key);
        return ValueTask.CompletedTask;
    }

    private string GetStorageKey(SecretReference reference)
    {
        if (!reference.IsDefined || reference.ProviderId != ProviderId)
        {
            throw new ArgumentException("Secret reference does not belong to this provider.", nameof(reference));
        }

        return StorageNamePrefix + reference.ProviderId.Value.ToString("N") + "." +
            reference.SecretId.Value.ToString("N");
    }
}
