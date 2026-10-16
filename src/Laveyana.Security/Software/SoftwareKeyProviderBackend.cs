using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Nonce;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Algorithms;
using Laveyana.Security.Lifecycle;
using Laveyana.Security.Diagnostics;

namespace Laveyana.Security.Software;

/// <summary>
/// Store-backed software key manager. Stores only protected key material, and uses the
/// pure lifecycle planner for every mutation. It also executes AES-GCM and HMAC on protected material.
/// </summary>
/// <remarks>
/// Requires a trusted store implementing atomic name claims and compare-and-swap updates,
/// and an authenticated protector that binds supplied associated context. A failed write
/// with unknown commit status is never retried automatically. This is not a durable store.
/// </remarks>
public sealed partial class SoftwareKeyProviderBackend : IAuthenticatedEncryptionBackend, IStreamingMacBackend, IManagedDerivationBackend, IConditionalKeyRotationBackend
{
    private static readonly IReadOnlyList<CapabilityId> ExecutableAesCapabilities =
        Array.AsReadOnly(new[] { WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt });
    private static readonly IReadOnlyList<CapabilityId> ExecutableMacCapabilities =
        Array.AsReadOnly(new[] { WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac });
    private static readonly IReadOnlyList<CapabilityId> ExecutableDerivationCapabilities =
        Array.AsReadOnly(new[] { WellKnownCapabilities.Derive });
    private readonly IKeyStore _store;
    private readonly IKeyStoreProtector _protector;
    private readonly IRollbackProtectedNonceAllocator? _nonceAllocator;
    private readonly SecurityObservability? _observability;

    /// <summary>Creates an adapter scoped to one durable, immutable provider identity.</summary>
    public SoftwareKeyProviderBackend(ProviderId providerId, IKeyStore store, IKeyStoreProtector protector,
        IRollbackProtectedNonceAllocator? nonceAllocator = null, SecurityObservability? observability = null)
    {
        if (!providerId.IsDefined)
        {
            throw new ArgumentException("Provider must be defined.", nameof(providerId));
        }

        ProviderId = providerId;
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _nonceAllocator = nonceAllocator;
        _observability = observability;
        if (!_protector.CurrentReference.IsDefined)
        {
            throw new ArgumentException("Protector must declare a defined reference.", nameof(protector));
        }
    }

    private ValueTask<T> Observe<T>(SecurityOperation operation,
        Func<CancellationToken, ValueTask<T>> action, CancellationToken cancellationToken) =>
        _observability is null ? action(cancellationToken) :
        _observability.ObserveAsync(operation, action, cancellationToken);

    private ValueTask Observe(SecurityOperation operation,
        Func<CancellationToken, ValueTask> action, CancellationToken cancellationToken) =>
        _observability is null ? action(cancellationToken) :
        _observability.ObserveAsync(operation, action, cancellationToken);

    /// <summary>Gets the stable provider identity used by all stored key references.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Advertises available managed AEAD, MAC and HKDF execution capabilities.</summary>
    public ValueTask<ProviderCapabilitySnapshot> GetCapabilitiesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(new ProviderCapabilitySnapshot(ProviderId,
            AesGcm.IsSupported
                ? ExecutableAesCapabilities.Concat(ExecutableMacCapabilities).Concat(ExecutableDerivationCapabilities).ToArray()
                : ExecutableMacCapabilities.Concat(ExecutableDerivationCapabilities).ToArray()));
    }

    /// <summary>Looks up an exact provider-scoped name and validates authenticated metadata.</summary>
    public async ValueTask<KeyDescriptor?> FindByNameAsync(KeyName name, CancellationToken cancellationToken = default)
    {
        Require(name.IsDefined);
        KeyStoreEntry? entry = await _store.FindByNameAsync(ProviderId, name, cancellationToken).ConfigureAwait(false);
        if (entry is null)
        {
            return null;
        }

        if (entry.ProviderId != ProviderId || entry.Name != name)
        {
            throw new InvalidOperationException("Store returned the wrong name binding.");
        }

        return (await ReadAsync(entry, cancellationToken).ConfigureAwait(false)).Describe();
    }

    /// <summary>Retrieves a logical key by its immutable generation identity.</summary>
    public async ValueTask<KeyDescriptor?> FindLogicalAsync(LogicalKeyHandle handle,
        CancellationToken cancellationToken = default)
    {
        Validate(handle);
        KeyStoreEntry? entry = await _store.FindByIdAsync(ProviderId, handle.KeyId, cancellationToken).ConfigureAwait(false);
        if (entry is null)
        {
            return null;
        }

        RequireEntryIdentity(entry, handle.KeyId);
        return (await ReadAsync(entry, cancellationToken).ConfigureAwait(false)).Describe();
    }

    /// <summary>Retrieves an exact version snapshot, including Deleted tombstones.</summary>
    public async ValueTask<KeyVersionDescriptor?> FindExactAsync(ExactKeyHandle handle,
        CancellationToken cancellationToken = default)
    {
        Validate(handle.Logical);
        if (!handle.IsDefined)
        {
            throw new ArgumentException("Exact handle must be defined.", nameof(handle));
        }

        KeyStoreEntry? entry = await _store.FindByIdAsync(ProviderId, handle.Reference.KeyId, cancellationToken).ConfigureAwait(false);
        if (entry is null)
        {
            return null;
        }

        RequireEntryIdentity(entry, handle.Reference.KeyId);
        SoftwareKeyMetadata metadata = await ReadAsync(entry, cancellationToken).ConfigureAwait(false);
        KeyLifecycleVersion? version = metadata.Lifecycle.Find(handle.Reference.Version);
        if (version is null)
        {
            return null;
        }

        if (version.State != KeyVersionState.Deleted)
        {
            KeyStoreMaterialReadResult material = await _store.ReadMaterialAsync(handle.Reference,
                entry.Revision, cancellationToken).ConfigureAwait(false);
            if (material.Status != KeyStoreMaterialReadStatus.Found || material.ProtectedMaterial is null)
            {
                throw new InvalidOperationException("The protected key material is missing or changed during the read.");
            }
        }

        return metadata.DescribeVersion(handle.Reference.Version);
    }

    /// <summary>Creates a generation with one Active version using fresh CSPRNG material.</summary>
    public ValueTask<KeyDescriptor> CreateAsync(KeyName name, AlgorithmId algorithm,
        IEnumerable<CapabilityId> capabilities, CancellationToken cancellationToken = default) =>
        CreateAsync(name, algorithm, capabilities, default(SoftwareKeyRetention), cancellationToken);

    /// <summary>Creates an Active version with an authoritative deletion constraint.</summary>
    public ValueTask<KeyDescriptor> CreateAsync(KeyName name, AlgorithmId algorithm,
        IEnumerable<CapabilityId> capabilities, SoftwareKeyRetention retention,
        CancellationToken cancellationToken = default) =>
        Observe(SecurityOperation.CreateKey,
            ct => CreateCoreAsync(name, algorithm, capabilities, retention, ct), cancellationToken);

    private async ValueTask<KeyDescriptor> CreateCoreAsync(KeyName name, AlgorithmId algorithm,
        IEnumerable<CapabilityId> capabilities, SoftwareKeyRetention retention,
        CancellationToken cancellationToken)
    {
        Require(name.IsDefined);
        CapabilityId[] copy = ValidateProfile(algorithm, capabilities);
        cancellationToken.ThrowIfCancellationRequested();
        KeyId key = KeyId.New();
        SoftwareKeyMetadata metadata = new(name, KeyKind.Symmetric, algorithm, copy,
            KeyLifecyclePlanner.Create(ProviderId, key, retention.ToConstraint()));
        KeyReference reference = new(ProviderId, key, new KeyVersion(1));
        ProtectedStoreEnvelope material = await GenerateProtectedMaterialAsync(reference, cancellationToken)
            .ConfigureAwait(false);
        ProtectedStoreEnvelope protection = await ProtectMetadataAsync(metadata, new KeyStoreRevision(1),
            cancellationToken).ConfigureAwait(false);
        KeyStoreCreateRequest request = new(ProviderId, key, name, protection,
            [KeyStoreMaterialChange.Upsert(reference, material)]);
        KeyStoreMutationResult result = await CommitCreateAsync(request, cancellationToken).ConfigureAwait(false);
        return result.Status switch
        {
            KeyStoreMutationStatus.Applied => ValidateRevision(result, 1, metadata).Describe(),
            KeyStoreMutationStatus.NameTaken => throw new SoftwareKeyConflictException("NameTaken"),
            KeyStoreMutationStatus.KeyAlreadyExists => throw new SoftwareKeyConflictException("KeyAlreadyExists"),
            _ => throw UnknownResult("create")
        };
    }

    /// <summary>
    /// Gets an existing generation or attempts an atomic create. A racing creator's protected
    /// candidate material is never stored; a winner is returned only if its profile matches.
    /// </summary>
    public ValueTask<KeyDescriptor> GetOrCreateAsync(KeyName name, AlgorithmId algorithm,
        IEnumerable<CapabilityId> capabilities, CancellationToken cancellationToken = default) =>
        GetOrCreateAsync(name, algorithm, capabilities, default(SoftwareKeyRetention), cancellationToken);

    /// <summary>Gets or creates only when the entire key profile and initial retention match.</summary>
    public async ValueTask<KeyDescriptor> GetOrCreateAsync(KeyName name, AlgorithmId algorithm,
        IEnumerable<CapabilityId> capabilities, SoftwareKeyRetention retention,
        CancellationToken cancellationToken = default)
    {
        Require(name.IsDefined);
        CapabilityId[] copy = ValidateProfile(algorithm, capabilities);
        KeyStoreEntry? existing = await _store.FindByNameAsync(ProviderId, name, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            if (existing.Name != name || existing.ProviderId != ProviderId)
            {
                throw new InvalidOperationException("Store returned the wrong name binding.");
            }

            return CheckProfile(await ReadAsync(existing, cancellationToken).ConfigureAwait(false), algorithm, copy, retention);
        }

        try
        {
            return await CreateAsync(name, algorithm, copy, retention, cancellationToken).ConfigureAwait(false);
        }
        catch (SoftwareKeyConflictException ex) when (ex.Reason == "NameTaken")
        {
            KeyStoreEntry? winner = await _store.FindByNameAsync(ProviderId, name, cancellationToken).ConfigureAwait(false);
            if (winner is null)
            {
                throw new SoftwareKeyConflictException("NameChangedDuringRace");
            }

            if (winner.Name != name || winner.ProviderId != ProviderId)
            {
                throw new InvalidOperationException("Store returned the wrong name binding.");
            }

            return CheckProfile(await ReadAsync(winner, cancellationToken).ConfigureAwait(false), algorithm, copy, retention);
        }
    }

    /// <summary>Reserves and commits the next Pending version together with protected material.</summary>
    public ValueTask<KeyVersionDescriptor> CreateVersionAsync(LogicalKeyHandle handle,
        CancellationToken cancellationToken = default) =>
        CreateVersionAsync(handle, default(SoftwareKeyRetention), cancellationToken);

    /// <summary>Reserves Pending material with an explicit authoritative retention guard.</summary>
    public async ValueTask<KeyVersionDescriptor> CreateVersionAsync(LogicalKeyHandle handle,
        SoftwareKeyRetention retention, CancellationToken cancellationToken = default)
    {
        SoftwareKeyMetadata updated = await ChangeAsync(handle,
            snapshot => KeyLifecyclePlanner.CreatePendingVersion(snapshot, retention.ToConstraint()),
            true, cancellationToken).ConfigureAwait(false);
        KeyLifecycleVersion pending = updated.Lifecycle.Versions.Single(x => x.State == KeyVersionState.Pending);
        return updated.DescribeVersion(pending.Version);
    }

    /// <summary>Atomically activates a previously committed Pending version.</summary>
    public ValueTask<KeyDescriptor> ActivateAsync(LogicalKeyHandle handle, KeyVersion version,
        CancellationToken cancellationToken = default) =>
        ChangeDescriptorAsync(handle, snapshot => KeyLifecyclePlanner.Activate(snapshot, version), false, cancellationToken);

    /// <summary>Creates and activates new material in one conditional aggregate transaction.</summary>
    public ValueTask<KeyDescriptor> RotateAsync(LogicalKeyHandle handle,
        CancellationToken cancellationToken = default) =>
        RotateAsync(handle, default(SoftwareKeyRetention), cancellationToken);

    /// <summary>Rotates immediately while recording retention for the new Active version.</summary>
    public ValueTask<KeyDescriptor> RotateAsync(LogicalKeyHandle handle,
        SoftwareKeyRetention retention, CancellationToken cancellationToken = default) =>
        Observe(SecurityOperation.RotateKey,
            ct => ChangeDescriptorAsync(handle, snapshot => KeyLifecyclePlanner.Rotate(snapshot, retention.ToConstraint()),
                true, ct), cancellationToken);

    /// <summary>
    /// Rotates only when the authoritative active version is the caller's expected version.
    /// The version fence is checked against the state used for the same CAS commit.
    /// </summary>
    public ValueTask<KeyDescriptor> RotateIfCurrentAsync(LogicalKeyHandle handle,
        KeyVersion expectedActiveVersion, CancellationToken cancellationToken = default)
    {
        if (!expectedActiveVersion.IsDefined)
        {
            throw new ArgumentException("An expected active version is required.", nameof(expectedActiveVersion));
        }

        return Observe(SecurityOperation.RotateKey, ct => ChangeDescriptorAsync(handle, snapshot =>
        {
            if (snapshot.ActiveVersion != expectedActiveVersion)
            {
                throw new SoftwareKeyConflictException("ActiveVersionChanged");
            }

            return KeyLifecyclePlanner.Rotate(snapshot);
        }, true, ct), cancellationToken);
    }

    /// <summary>Permanently retires the logical generation and its active version.</summary>
    public ValueTask<KeyDescriptor> RetireAsync(LogicalKeyHandle handle,
        CancellationToken cancellationToken = default) =>
        Observe(SecurityOperation.RetireKey,
            ct => ChangeDescriptorAsync(handle, KeyLifecyclePlanner.RetireKey, false, ct), cancellationToken);

    /// <summary>Discards never-activated Pending material, retaining its version tombstone.</summary>
    public ValueTask<KeyDescriptor> DiscardAsync(LogicalKeyHandle handle, KeyVersion version,
        CancellationToken cancellationToken = default) =>
        ChangeDescriptorAsync(handle, snapshot => KeyLifecyclePlanner.DiscardPending(snapshot, version), false,
            cancellationToken);

    /// <summary>Deletes retired material only when its authoritative retention allows it.</summary>
    public ValueTask<KeyDescriptor> DeleteVersionAsync(LogicalKeyHandle handle, KeyVersion version,
        DateTimeOffset nowUtc, CancellationToken cancellationToken = default) =>
        ChangeDescriptorAsync(handle, snapshot => KeyLifecyclePlanner.DeleteVersion(snapshot, version, nowUtc),
            false, cancellationToken);

    /// <summary>Explicitly destructive individual version deletion; never deletes Active.</summary>
    public ValueTask<KeyDescriptor> ForceDeleteVersionAsync(LogicalKeyHandle handle, KeyVersion version,
        CancellationToken cancellationToken = default) =>
        ChangeDescriptorAsync(handle, snapshot => KeyLifecyclePlanner.ForceDeleteVersion(snapshot, version),
            false, cancellationToken);

    /// <summary>Deletes a Retired generation and releases its name only after an atomic commit.</summary>
    public ValueTask DeleteAsync(LogicalKeyHandle handle, DateTimeOffset nowUtc,
        CancellationToken cancellationToken = default) =>
        Observe(SecurityOperation.DeleteKey,
            ct => DeleteAggregateAsync(handle, snapshot => KeyLifecyclePlanner.DeleteKey(snapshot, nowUtc), ct),
            cancellationToken);

    /// <summary>Explicitly destructive full-generation cascade, including current Active material.</summary>
    public ValueTask ForceDeleteAsync(LogicalKeyHandle handle, CancellationToken cancellationToken = default) =>
        Observe(SecurityOperation.DeleteKey,
            ct => DeleteAggregateAsync(handle, KeyLifecyclePlanner.ForceDeleteKey, ct), cancellationToken);

    private async ValueTask<KeyDescriptor> ChangeDescriptorAsync(LogicalKeyHandle handle,
        Func<KeyLifecycleSnapshot, KeyLifecycleTransition> planner, bool generateMaterial,
        CancellationToken cancellationToken) =>
        (await ChangeAsync(handle, planner, generateMaterial, cancellationToken).ConfigureAwait(false)).Describe();

    private async ValueTask<SoftwareKeyMetadata> ChangeAsync(LogicalKeyHandle handle,
        Func<KeyLifecycleSnapshot, KeyLifecycleTransition> planner, bool generateMaterial,
        CancellationToken cancellationToken)
    {
        Validate(handle);
        KeyStoreEntry entry = await FindRequiredEntryAsync(handle, cancellationToken).ConfigureAwait(false);
        SoftwareKeyMetadata metadata = await ReadAsync(entry, cancellationToken).ConfigureAwait(false);
        KeyLifecycleTransition transition = planner(metadata.Lifecycle);
        if (transition.Disposition == KeyLifecycleDisposition.AlreadyApplied)
        {
            return metadata;
        }

        List<KeyStoreMaterialChange> changes = new();
        if (generateMaterial)
        {
            KeyVersion version = transition.AffectedVersion ?? throw new InvalidOperationException("No new version planned.");
            KeyReference reference = new(ProviderId, handle.KeyId, version);
            changes.Add(KeyStoreMaterialChange.Upsert(reference,
                await GenerateProtectedMaterialAsync(reference, cancellationToken).ConfigureAwait(false)));
        }
        else if (transition.AffectedVersion.HasValue &&
            transition.Current.Find(transition.AffectedVersion.Value)?.State == KeyVersionState.Deleted)
        {
            changes.Add(KeyStoreMaterialChange.Delete(new KeyReference(ProviderId, handle.KeyId,
                transition.AffectedVersion.Value)));
        }

        SoftwareKeyMetadata updated = metadata.WithLifecycle(transition.Current);
        KeyStoreRevision revision = NextRevision(entry.Revision);
        ProtectedStoreEnvelope protectedMetadata = await ProtectMetadataAsync(updated, revision, cancellationToken)
            .ConfigureAwait(false);
        KeyStoreReplaceRequest request = new(ProviderId, handle.KeyId, entry.Revision, protectedMetadata, changes);
        KeyStoreMutationResult result = await CommitReplaceAsync(request, cancellationToken).ConfigureAwait(false);
        return result.Status switch
        {
            KeyStoreMutationStatus.Applied => ValidateRevision(result, revision.Value, updated),
            KeyStoreMutationStatus.RevisionMismatch or KeyStoreMutationStatus.NotFound =>
                throw new SoftwareKeyConflictException("ConcurrentMutation"),
            _ => throw UnknownResult("replace")
        };
    }

    private async ValueTask DeleteAggregateAsync(LogicalKeyHandle handle,
        Func<KeyLifecycleSnapshot, KeyLifecycleTransition> planner, CancellationToken cancellationToken)
    {
        Validate(handle);
        KeyStoreEntry entry = await FindRequiredEntryAsync(handle, cancellationToken).ConfigureAwait(false);
        SoftwareKeyMetadata metadata = await ReadAsync(entry, cancellationToken).ConfigureAwait(false);
        _ = planner(metadata.Lifecycle);
        cancellationToken.ThrowIfCancellationRequested();
        KeyStoreMutationResult result;
        try
        {
            result = await _store.TryDeleteAsync(ProviderId, handle.KeyId, entry.Revision, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new SoftwareKeyCommitUncertainException(ex);
        }

        if (result.Status == KeyStoreMutationStatus.Applied && result.Revision is null)
        {
            return;
        }

        if (result.Status is KeyStoreMutationStatus.RevisionMismatch or KeyStoreMutationStatus.NotFound)
        {
            throw new SoftwareKeyConflictException("ConcurrentMutation");
        }

        throw UnknownResult("delete");
    }

    private async ValueTask<KeyStoreEntry> FindRequiredEntryAsync(LogicalKeyHandle handle,
        CancellationToken cancellationToken) =>
        await RequireCorrectEntryAsync(handle, cancellationToken).ConfigureAwait(false);

    private async ValueTask<KeyStoreEntry> RequireCorrectEntryAsync(LogicalKeyHandle handle,
        CancellationToken cancellationToken)
    {
        KeyStoreEntry entry = await _store.FindByIdAsync(ProviderId, handle.KeyId, cancellationToken)
            .ConfigureAwait(false) ?? throw new SoftwareKeyConflictException("KeyNotFound");
        RequireEntryIdentity(entry, handle.KeyId);
        return entry;
    }

    private void RequireEntryIdentity(KeyStoreEntry entry, KeyId expectedKey)
    {
        if (entry.ProviderId != ProviderId || entry.KeyId != expectedKey)
        {
            throw new InvalidOperationException("Store returned the wrong key identity.");
        }
    }

    private async ValueTask<SoftwareKeyMetadata> ReadAsync(KeyStoreEntry entry,
        CancellationToken cancellationToken)
    {
        if (entry.ProviderId != ProviderId || !entry.KeyId.IsDefined || !entry.Name.IsDefined ||
            !entry.Revision.IsDefined || entry.ProtectedMetadata.Purpose != ProtectionPurpose.Metadata)
        {
            throw new InvalidOperationException("Store returned inconsistent key identity.");
        }

        byte[] context = KeyStoreProtectionContext.ForMetadata(ProviderId, entry.KeyId, entry.Revision);
        using SensitiveMaterialLease lease = await _protector.UnprotectAsync(entry.ProtectedMetadata,
            ProtectionPurpose.Metadata, context, cancellationToken).ConfigureAwait(false);
        SoftwareKeyMetadata metadata = SoftwareKeyMetadataCodec.Decode(lease, ProviderId, entry.KeyId, entry.Name);
        if (metadata.Kind != KeyKind.Symmetric)
        {
            throw new InvalidOperationException("Unsupported stored software key type.");
        }

        _ = ValidateProfile(metadata.Algorithm, metadata.Capabilities);
        return metadata;
    }

    private async ValueTask<ProtectedStoreEnvelope> ProtectMetadataAsync(SoftwareKeyMetadata metadata,
        KeyStoreRevision revision, CancellationToken cancellationToken)
    {
        using SensitiveMaterialLease lease = SoftwareKeyMetadataCodec.Encode(metadata);
        return await _protector.ProtectAsync(lease, ProtectionPurpose.Metadata,
            KeyStoreProtectionContext.ForMetadata(ProviderId, metadata.Lifecycle.KeyId, revision),
            cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<ProtectedStoreEnvelope> GenerateProtectedMaterialAsync(KeyReference reference,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        using SensitiveMaterialLease lease = SensitiveMaterialLease.TakeOwnership(secret);
        return await _protector.ProtectAsync(lease, ProtectionPurpose.KeyMaterial,
            KeyStoreProtectionContext.ForKeyMaterial(reference), cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<KeyStoreMutationResult> CommitCreateAsync(KeyStoreCreateRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            return await _store.TryCreateAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new SoftwareKeyCommitUncertainException(ex);
        }
    }

    private async ValueTask<KeyStoreMutationResult> CommitReplaceAsync(KeyStoreReplaceRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            return await _store.TryReplaceAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new SoftwareKeyCommitUncertainException(ex);
        }
    }

    private static SoftwareKeyCommitUncertainException UnknownResult(string operation) =>
        new(new InvalidOperationException($"Store returned an inconsistent {operation} result."));

    private static KeyStoreRevision NextRevision(KeyStoreRevision revision) =>
        revision.Value == long.MaxValue ? throw new InvalidOperationException("Store revision exhausted.") :
            new KeyStoreRevision(checked(revision.Value + 1));

    private static SoftwareKeyMetadata ValidateRevision(KeyStoreMutationResult result,
        long expected, SoftwareKeyMetadata metadata)
    {
        if (result.Revision != new KeyStoreRevision(expected))
        {
            throw new SoftwareKeyCommitUncertainException(
                new InvalidOperationException("Store returned a nonconforming committed revision."));
        }

        return metadata;
    }

    private static KeyDescriptor CheckProfile(SoftwareKeyMetadata metadata, AlgorithmId algorithm,
        IReadOnlyList<CapabilityId> capabilities, SoftwareKeyRetention retention)
    {
        KeyRetentionConstraint initial = metadata.Lifecycle.Find(new KeyVersion(1))?.Retention ?? default;
        if (metadata.Kind != KeyKind.Symmetric || metadata.Algorithm != algorithm ||
            !metadata.Capabilities.SequenceEqual(capabilities) || initial != retention.ToConstraint())
        {
            throw new SoftwareKeyConflictException("ExistingNameHasDifferentProfile");
        }

        return metadata.Describe();
    }

    private static CapabilityId[] ValidateProfile(AlgorithmId algorithm, IEnumerable<CapabilityId> capabilities)
    {
        ArgumentNullException.ThrowIfNull(capabilities);
        AlgorithmPurpose purpose;
        CapabilityId[] allowed;
        if (algorithm == WellKnownAlgorithms.Aes256Gcm || algorithm == WellKnownAlgorithms.ChaCha20Poly1305)
        {
            purpose = AlgorithmPurpose.AuthenticatedEncryption;
            allowed = [WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt];
        }
        else if (algorithm == WellKnownAlgorithms.HmacSha256 || algorithm == WellKnownAlgorithms.HmacSha384 ||
            algorithm == WellKnownAlgorithms.HmacSha512)
        {
            purpose = AlgorithmPurpose.Mac;
            allowed = [WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac];
        }
        else if (algorithm == WellKnownAlgorithms.HkdfSha256)
        {
            purpose = AlgorithmPurpose.GeneralKdf;
            allowed = [WellKnownCapabilities.Derive];
        }
        else
        {
            throw new CryptographicException("No software managed key-generation profile for this algorithm.");
        }

        AlgorithmPolicy.EnsureAllowed(algorithm, purpose, AlgorithmUse.NewOperation);
        CapabilityId[] selected = capabilities.Take(65).ToArray();
        if (selected.Length is < 1 or > 64 || selected.Any(x => !x.IsDefined || !allowed.Contains(x)) ||
            selected.Distinct().Count() != selected.Length)
        {
            throw new ArgumentException("Requested key capabilities do not match this algorithm.", nameof(capabilities));
        }

        Array.Sort(selected, (a, b) => string.CompareOrdinal(a.Value, b.Value));
        return selected;
    }

    private void Validate(LogicalKeyHandle handle)
    {
        if (!handle.IsDefined || handle.ProviderId != ProviderId)
        {
            throw new ArgumentException("Logical handle is undefined.", nameof(handle));
        }
    }

    private static void Require(bool condition)
    {
        if (!condition)
        {
            throw new ArgumentException("A defined name is required.");
        }
    }
}
