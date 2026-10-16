using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Payloads;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Algorithms;
using Laveyana.Security.Diagnostics;

namespace Laveyana.Security.Software;

/// <summary>Managed HMAC operations on the authoritative protected software-key versions.</summary>
public sealed partial class SoftwareKeyProviderBackend
{
    /// <summary>Computes a full HMAC using the current Active version and records its exact identity.</summary>
    public ValueTask<MacResult> ComputeMacAsync(LogicalKeyHandle handle, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default) =>
        Observe(SecurityOperation.ComputeMac, ct => ComputeMacCoreAsync(handle, message, ct), cancellationToken);

    private async ValueTask<MacResult> ComputeMacCoreAsync(LogicalKeyHandle handle,
        ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
    {
        Validate(handle);
        CheckMacMessageLength(message.Length);
        cancellationToken.ThrowIfCancellationRequested();
        byte[] input = message.ToArray();
        try
        {
            KeyStoreEntry entry = await RequireCorrectEntryAsync(handle, cancellationToken).ConfigureAwait(false);
            SoftwareKeyMetadata metadata = await ReadAsync(entry, cancellationToken).ConfigureAwait(false);
            if (metadata.Lifecycle.State != LogicalKeyState.Active ||
                metadata.Lifecycle.ActiveVersion is not KeyVersion active)
            {
                throw new CryptographicException("MAC creation requires an Active key.");
            }

            RequireMacCapability(metadata, active, WellKnownCapabilities.Mac, true);
            KeyReference reference = new(ProviderId, handle.KeyId, active);
            using SensitiveMaterialLease key = await ReadKeyMaterialAsync(reference, entry.Revision,
                cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            byte[]? tag = null;
            try
            {
                key.UseMaterial(material => tag = ComputeHmac(metadata.Algorithm, material, input));
                return new MacResult(reference, metadata.Algorithm, tag!);
            }
            finally
            {
                if (tag is not null)
                {
                    CryptographicOperations.ZeroMemory(tag);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    /// <summary>Returns false solely for a mismatching tag. Missing key, unauthorized use and I/O errors throw.</summary>
    public ValueTask<bool> VerifyMacAsync(MacResult result, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default) =>
        Observe(SecurityOperation.VerifyMac, ct => VerifyMacCoreAsync(result, message, ct), cancellationToken);

    private async ValueTask<bool> VerifyMacCoreAsync(MacResult result,
        ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(result);
        Validate(new LogicalKeyHandle(result.Reference.ProviderId, result.Reference.KeyId));
        CheckMacMessageLength(message.Length);
        cancellationToken.ThrowIfCancellationRequested();
        byte[] input = message.ToArray();
        byte[] expected = result.ExportTagCopy();
        try
        {
            KeyStoreEntry entry = await RequireCorrectEntryAsync(
                new LogicalKeyHandle(result.Reference.ProviderId, result.Reference.KeyId), cancellationToken)
                .ConfigureAwait(false);
            SoftwareKeyMetadata metadata = await ReadAsync(entry, cancellationToken).ConfigureAwait(false);
            RequireMacCapability(metadata, result.Reference.Version, WellKnownCapabilities.VerifyMac, false);
            if (metadata.Algorithm != result.Algorithm)
            {
                throw new CryptographicException("The MAC algorithm differs from the stored key profile.");
            }

            using SensitiveMaterialLease key = await ReadKeyMaterialAsync(result.Reference, entry.Revision,
                cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            bool verified = false;
            key.UseMaterial(material =>
            {
                byte[] calculated = ComputeHmac(metadata.Algorithm, material, input);
                try
                {
                    verified = CryptographicOperations.FixedTimeEquals(calculated, expected);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(calculated);
                }
            });
            return verified;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    private static byte[] ComputeHmac(AlgorithmId algorithm, ReadOnlySpan<byte> key, ReadOnlySpan<byte> message) =>
        algorithm == WellKnownAlgorithms.HmacSha256 ? HMACSHA256.HashData(key, message) :
        algorithm == WellKnownAlgorithms.HmacSha384 ? HMACSHA384.HashData(key, message) :
        algorithm == WellKnownAlgorithms.HmacSha512 ? HMACSHA512.HashData(key, message) :
        throw new CryptographicException("Unsupported HMAC algorithm; no fallback is permitted.");

    private static void CheckMacMessageLength(int count)
    {
        if (count is < 0 or > 16 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "Managed HMAC message limit is 16 MiB.");
        }
    }

    private static void RequireMacCapability(SoftwareKeyMetadata metadata, KeyVersion version,
        CapabilityId capability, bool forward)
    {
        if (metadata.Kind != KeyKind.Symmetric ||
            (metadata.Algorithm != WellKnownAlgorithms.HmacSha256 &&
             metadata.Algorithm != WellKnownAlgorithms.HmacSha384 &&
             metadata.Algorithm != WellKnownAlgorithms.HmacSha512))
        {
            throw new CryptographicException("Only full-length HMAC-SHA-2 is supported.");
        }

        AlgorithmPolicy.EnsureAllowed(metadata.Algorithm, AlgorithmPurpose.Mac,
            forward ? AlgorithmUse.NewOperation : AlgorithmUse.HistoricalVerification);
        KeyVersionState state = metadata.Lifecycle.Find(version)?.State ?? KeyVersionState.Unspecified;
        if (!metadata.Capabilities.Contains(capability) || (forward && state != KeyVersionState.Active) ||
            (!forward && state is not (KeyVersionState.Active or KeyVersionState.Retired)))
        {
            throw new CryptographicException("The requested HMAC operation is forbidden for this version.");
        }
    }
}
