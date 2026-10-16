using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Payloads;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Abstractions.Streaming;
using Laveyana.Security.Streaming;

namespace Laveyana.Security.Software;

/// <summary>Provider-backed, exact-version streaming HMAC with bounded input memory.</summary>
public sealed partial class SoftwareKeyProviderBackend
{
    /// <inheritdoc/>
    public async Task<MacResult> ComputeMacStreamAsync(LogicalKeyHandle handle, Stream message,
        StreamProcessingOptions? options = null, CancellationToken cancellationToken = default)
    {
        Validate(handle);
        ArgumentNullException.ThrowIfNull(message);
        cancellationToken.ThrowIfCancellationRequested();
        KeyStoreEntry entry = await RequireCorrectEntryAsync(handle, cancellationToken).ConfigureAwait(false);
        SoftwareKeyMetadata metadata = await ReadAsync(entry, cancellationToken).ConfigureAwait(false);
        if (metadata.Lifecycle.State != LogicalKeyState.Active ||
            metadata.Lifecycle.ActiveVersion is not KeyVersion active)
        {
            throw new CryptographicException("MAC creation requires an Active key.");
        }
        RequireMacCapability(metadata, active, WellKnownCapabilities.Mac, true);
        KeyReference reference = new(ProviderId, handle.KeyId, active);
        using IncrementalHash hmac = await OpenHmacAsync(reference, entry.Revision, metadata.Algorithm,
            cancellationToken).ConfigureAwait(false);
        await StreamHashPump.PumpAsync(message, hmac, options, cancellationToken).ConfigureAwait(false);
        await RequireUnchangedMacRevisionAsync(handle, entry.Revision, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        byte[] tag = hmac.GetHashAndReset();
        try
        {
            return new MacResult(reference, metadata.Algorithm, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    /// <inheritdoc/>
    public async Task<bool> VerifyMacStreamAsync(MacResult result, Stream message,
        StreamProcessingOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(message);
        LogicalKeyHandle handle = new(result.Reference.ProviderId, result.Reference.KeyId);
        Validate(handle);
        cancellationToken.ThrowIfCancellationRequested();
        KeyStoreEntry entry = await RequireCorrectEntryAsync(handle, cancellationToken).ConfigureAwait(false);
        SoftwareKeyMetadata metadata = await ReadAsync(entry, cancellationToken).ConfigureAwait(false);
        RequireMacCapability(metadata, result.Reference.Version, WellKnownCapabilities.VerifyMac, false);
        if (metadata.Algorithm != result.Algorithm)
        {
            throw new CryptographicException("The MAC algorithm differs from the stored key profile.");
        }
        using IncrementalHash hmac = await OpenHmacAsync(result.Reference, entry.Revision, metadata.Algorithm,
            cancellationToken).ConfigureAwait(false);
        await StreamHashPump.PumpAsync(message, hmac, options, cancellationToken).ConfigureAwait(false);
        await RequireUnchangedMacRevisionAsync(handle, entry.Revision, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        byte[] actual = hmac.GetHashAndReset();
        byte[] expected = result.ExportTagCopy();
        try
        {
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    private async Task RequireUnchangedMacRevisionAsync(LogicalKeyHandle handle, KeyStoreRevision initial,
        CancellationToken cancellationToken)
    {
        KeyStoreEntry current = await RequireCorrectEntryAsync(handle, cancellationToken).ConfigureAwait(false);
        if (current.Revision != initial)
        {
            throw new SoftwareKeyConflictException("KeyChangedDuringStreamingMac");
        }
    }

    private async Task<IncrementalHash> OpenHmacAsync(KeyReference reference, KeyStoreRevision revision,
        AlgorithmId algorithm, CancellationToken cancellationToken)
    {
        using SensitiveMaterialLease key = await ReadKeyMaterialAsync(reference, revision,
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        HashAlgorithmName name = algorithm == WellKnownAlgorithms.HmacSha256 ? HashAlgorithmName.SHA256 :
            algorithm == WellKnownAlgorithms.HmacSha384 ? HashAlgorithmName.SHA384 :
            algorithm == WellKnownAlgorithms.HmacSha512 ? HashAlgorithmName.SHA512 :
            throw new CryptographicException("Unsupported HMAC algorithm; no fallback is permitted.");
        IncrementalHash? instance = null;
        key.UseMaterial(material => instance = IncrementalHash.CreateHMAC(name, material));
        return instance!;
    }
}
