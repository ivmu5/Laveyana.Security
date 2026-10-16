using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Protection;

namespace Laveyana.Security.Software;

/// <summary>Explicit, per-generation, CAS-atomic re-protection without cryptographic-key rotation.</summary>
/// <remarks>
/// Requires an IKeyStore with atomic aggregate replacement. A changed revision fails definitively;
/// an exception at the commit boundary is an unknown outcome and must be reconciled by reading
/// authoritative state before any retry. This workflow never exports long-term material to callers
/// and never changes KeyId, KeyVersion, algorithm, lifecycle or retention. It does not detect
/// rollback of valid older snapshots, repair compromised key material, or enumerate the store.
/// </remarks>
public sealed class SoftwareKeyReprotectionService
{
    private const int MaximumMaterialChanges = 128;
    private readonly ProviderId _provider;
    private readonly IKeyStore _store;
    private readonly ProtectorGenerationRouter _router;

    /// <summary>Creates an explicit migration coordinator with one current-write protector.</summary>
    public SoftwareKeyReprotectionService(ProviderId providerId, IKeyStore store,
        ProtectorGenerationRouter router)
    {
        if (!providerId.IsDefined)
        {
            throw new ArgumentException("Provider identity must be defined.", nameof(providerId));
        }

        _provider = providerId;
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _router = router ?? throw new ArgumentNullException(nameof(router));
    }

    /// <summary>
    /// Reads and authenticates a single aggregate and every live material version before
    /// replacing metadata and only legacy material in one compare-and-swap transaction.
    /// </summary>
    public async ValueTask<KeyReprotectionResult> ReprotectAsync(LogicalKeyHandle handle,
        CancellationToken cancellationToken = default)
    {
        if (!handle.IsDefined || handle.ProviderId != _provider)
        {
            throw new ArgumentException("An exact provider-scoped logical handle is required.", nameof(handle));
        }

        cancellationToken.ThrowIfCancellationRequested();
        KeyStoreEntry entry = await _store.FindByIdAsync(_provider, handle.KeyId, cancellationToken)
            .ConfigureAwait(false) ?? throw new SoftwareKeyConflictException("KeyNotFound");
        if (entry.ProviderId != _provider || entry.KeyId != handle.KeyId || !entry.Name.IsDefined ||
            !entry.Revision.IsDefined || entry.ProtectedMetadata.Purpose != ProtectionPurpose.Metadata)
        {
            throw new InvalidOperationException("Store returned an inconsistent aggregate identity.");
        }

        EnsureReadable(entry.ProtectedMetadata);
        SoftwareKeyMetadata metadata;
        bool metadataUsesCurrentSchema = false;
        using (SensitiveMaterialLease plaintextMetadata = await _router.UnprotectAsync(entry.ProtectedMetadata,
            ProtectionPurpose.Metadata, KeyStoreProtectionContext.ForMetadata(_provider, handle.KeyId, entry.Revision),
            cancellationToken).ConfigureAwait(false))
        {
            plaintextMetadata.UseMaterial(bytes => metadataUsesCurrentSchema = bytes.Length >= 6 &&
                bytes[..4].SequenceEqual("LSMD"u8) && bytes[4] == 2 && bytes[5] == 0);
            metadata = SoftwareKeyMetadataCodec.Decode(plaintextMetadata, _provider, handle.KeyId, entry.Name);
        }
        if (metadata.Kind != KeyKind.Symmetric)
        {
            throw new InvalidOperationException("Unsupported software key metadata kind.");
        }

        // Re-protection is one aggregate CAS, not 128 partial transactions.
        KeyVersion[] versions = metadata.Lifecycle.Versions
            .Where(version => version.State != KeyVersionState.Deleted)
            .Select(version => version.Version).ToArray();
        if (versions.Length > MaximumMaterialChanges)
        {
            throw new InvalidOperationException("The aggregate exceeds the atomic re-protection budget.");
        }

        List<KeyStoreMaterialChange> changes = new(versions.Length);
        foreach (KeyVersion version in versions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            KeyReference reference = new(_provider, handle.KeyId, version);
            KeyStoreMaterialReadResult read = await _store.ReadMaterialAsync(reference, entry.Revision,
                cancellationToken).ConfigureAwait(false);
            if (read.Status == KeyStoreMaterialReadStatus.RevisionMismatch)
            {
                throw new SoftwareKeyConflictException("ConcurrentMutation");
            }

            if (read.Status != KeyStoreMaterialReadStatus.Found || read.ProtectedMaterial is null)
            {
                throw new InvalidOperationException("Authoritative key material is missing or inconsistent.");
            }

            ProtectedStoreEnvelope envelope = read.ProtectedMaterial;
            EnsureReadable(envelope);
            // Authentication is mandatory even for already-current material, before reporting no-op.
            using SensitiveMaterialLease material = await _router.UnprotectAsync(envelope,
                ProtectionPurpose.KeyMaterial, KeyStoreProtectionContext.ForKeyMaterial(reference),
                cancellationToken).ConfigureAwait(false);
            if (envelope.Protector != _router.CurrentReference)
            {
                byte[] materialContext = KeyStoreProtectionContext.ForKeyMaterial(reference);
                ProtectedStoreEnvelope replacement = await _router.ProtectAsync(material,
                    ProtectionPurpose.KeyMaterial, materialContext, cancellationToken).ConfigureAwait(false);
                await VerifyRoundTripAsync(material, replacement, ProtectionPurpose.KeyMaterial,
                    materialContext, cancellationToken).ConfigureAwait(false);
                changes.Add(KeyStoreMaterialChange.Upsert(reference, replacement));
            }
        }

        if (entry.ProtectedMetadata.Protector == _router.CurrentReference &&
            metadataUsesCurrentSchema && changes.Count == 0)
        {
            // A no-op has no CAS point: at least reject an already observed stale read.
            KeyStoreEntry? latest = await _store.FindByIdAsync(_provider, handle.KeyId, cancellationToken)
                .ConfigureAwait(false);
            if (latest is null || latest.ProviderId != _provider || latest.KeyId != handle.KeyId ||
                latest.Revision != entry.Revision || latest.Name != entry.Name)
            {
                throw new SoftwareKeyConflictException("ConcurrentMutation");
            }

            return new KeyReprotectionResult(KeyReprotectionStatus.AlreadyCurrent, entry.Revision);
        }

        if (entry.Revision.Value == long.MaxValue)
        {
            throw new InvalidOperationException("Store revision exhausted.");
        }

        KeyStoreRevision next = new(checked(entry.Revision.Value + 1));
        using SensitiveMaterialLease newMetadata = SoftwareKeyMetadataCodec.Encode(metadata);
        byte[] metadataContext = KeyStoreProtectionContext.ForMetadata(_provider, handle.KeyId, next);
        ProtectedStoreEnvelope protectedMetadata = await _router.ProtectAsync(newMetadata,
            ProtectionPurpose.Metadata, metadataContext, cancellationToken).ConfigureAwait(false);
        await VerifyRoundTripAsync(newMetadata, protectedMetadata, ProtectionPurpose.Metadata,
            metadataContext, cancellationToken).ConfigureAwait(false);
        KeyStoreReplaceRequest request = new(_provider, handle.KeyId, entry.Revision, protectedMetadata, changes);

        cancellationToken.ThrowIfCancellationRequested();
        KeyStoreMutationResult result;
        try
        {
            result = await _store.TryReplaceAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new SoftwareKeyCommitUncertainException(ex);
        }

        return result.Status switch
        {
            KeyStoreMutationStatus.Applied when result.Revision == next =>
                new KeyReprotectionResult(KeyReprotectionStatus.Reprotected, next),
            KeyStoreMutationStatus.RevisionMismatch or KeyStoreMutationStatus.NotFound =>
                throw new SoftwareKeyConflictException("ConcurrentMutation"),
            _ => throw new SoftwareKeyCommitUncertainException(
                new InvalidOperationException("Store returned an inconsistent migration commit result."))
        };
    }

    private async ValueTask VerifyRoundTripAsync(SensitiveMaterialLease original,
        ProtectedStoreEnvelope protectedResult, ProtectionPurpose purpose, byte[] context,
        CancellationToken cancellationToken)
    {
        using SensitiveMaterialLease restored = await _router.UnprotectAsync(protectedResult, purpose,
            context, cancellationToken).ConfigureAwait(false);
        bool same = false;
        byte[]? decryptedCopy = null;
        try
        {
            // Do not capture a ref-like span in a nested callback.
            // The temporary copy is wiped even if the comparison fails.
            restored.UseMaterial(decrypted => decryptedCopy = decrypted.ToArray());
            byte[] snapshot = decryptedCopy ??
                throw new InvalidOperationException("Protector returned no material for verification.");
            original.UseMaterial(plaintext => same = plaintext.Length == snapshot.Length &&
                CryptographicOperations.FixedTimeEquals(plaintext, snapshot));
        }
        finally
        {
            if (decryptedCopy is not null)
            {
                CryptographicOperations.ZeroMemory(decryptedCopy);
            }
        }
        if (!same)
        {
            throw new CryptographicException("Current protector failed its pre-commit round-trip check.");
        }
    }

    private void EnsureReadable(ProtectedStoreEnvelope envelope)
    {
        if (_router.Classify(envelope.Protector) is ProtectorGenerationClassification.Unknown or
            ProtectorGenerationClassification.Compromised)
        {
            throw new CryptographicException(
                "Unknown or compromised protector generation cannot undergo ordinary re-protection.");
        }
    }
}
