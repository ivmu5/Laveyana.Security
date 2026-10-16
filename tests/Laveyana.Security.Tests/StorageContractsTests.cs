using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Nonce;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Contract validation and concurrency semantics using an in-memory, test-only external store.</summary>
[TestFixture]
internal sealed class StorageContractsTests
{
    private static readonly ProviderId Provider = ProviderId.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly ProviderId OtherProvider = ProviderId.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly KeyId Key = KeyId.Parse("33333333-3333-4333-8333-333333333333");
    private static readonly KeyId OtherKey = KeyId.Parse("44444444-4444-4444-8444-444444444444");
    private static readonly KeyName Name = new("PrimaryKey");
    private static readonly ProtectorReference Protector = new("ProductionProtector", 1);

    private static ProtectedStoreEnvelope Meta(byte value = 1) =>
        new(Protector, ProtectionPurpose.Metadata, new byte[] { value });

    private static ProtectedStoreEnvelope Material(byte value = 1) =>
        new(Protector, ProtectionPurpose.KeyMaterial, new byte[] { value });

    private static KeyReference Ref(long version, ProviderId? provider = null, KeyId? key = null) =>
        new(provider ?? Provider, key ?? Key, new KeyVersion(version));

    private static KeyStoreCreateRequest Create(KeyId? key = null, KeyName? name = null) =>
        new(Provider, key ?? Key, name ?? Name, Meta(), [KeyStoreMaterialChange.Upsert(
            new KeyReference(Provider, key ?? Key, new KeyVersion(1)), Material())]);

    [Test]
    public void ContractsBelongOnlyToAbstractions()
    {
        Type marker = typeof(ProviderId);
        Type[] contracts = [typeof(IKeyStore), typeof(IKeyStoreProtector),
            typeof(IRollbackProtectedNonceAllocator), typeof(KeyStoreEntry),
            typeof(KeyStoreCreateRequest), typeof(ProtectedStoreEnvelope)];
        Assert.That(contracts.All(type => type.Assembly == marker.Assembly), Is.True);
        Assert.That(typeof(IKeyStore).GetInterfaces(), Is.Empty);
        Assert.That(typeof(IKeyStore).GetMethod("ReserveAsync"), Is.Null);
        Assert.That(new KeyStoreCapabilities(false).ProvidesRollbackProtection, Is.False);
    }

    [Test]
    public void ProtectorIdentityCanonicalParsingAndStrictValidation()
    {
        Assert.That(ProtectorReference.Parse("Protector_1/5"), Is.EqualTo(new ProtectorReference("Protector_1", 5)));
        foreach (string invalid in new[] { "", "x/0", "x/01", "x/-1", "x/1/2", " x/1", "x/1 ", "x/2147483648" })
        {
            Assert.That(ProtectorReference.TryParse(invalid, out _), Is.False, invalid);
        }

        Assert.That(default(ProtectorReference).IsDefined, Is.False);
        Assert.Throws<InvalidOperationException>(() => default(ProtectorReference).ToString());
        Assert.Throws<ArgumentException>(() => new ProtectorReference("/", 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ProtectorReference("Id", 0));
    }

    [Test]
    public void EncodedEnvelopeCannotBeMutatedByCaller()
    {
        byte[] original = [10, 20, 30];
        ProtectedStoreEnvelope envelope = new(Protector, ProtectionPurpose.Metadata, original);
        original[0] = 99;
        byte[] exported = envelope.ExportEncodedCopy();
        exported[0] = 98;
        Assert.That(envelope.ExportEncodedCopy(), Is.EqualTo(new byte[] { 10, 20, 30 }));
        Assert.That(envelope.ToString(), Does.Not.Contain("10"));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ProtectedStoreEnvelope(Protector, ProtectionPurpose.Metadata, []));
        Assert.Throws<ArgumentException>(() => new ProtectedStoreEnvelope(Protector, ProtectionPurpose.Unspecified, [1]));
        Assert.Throws<ArgumentException>(() => new ProtectedStoreEnvelope(default, ProtectionPurpose.Metadata, [1]));
    }

    [Test]
    public void CreateAndReplaceRequestsRejectCrossKeyMaterialsAndDuplicateVersions()
    {
        Assert.Throws<ArgumentException>(() => new KeyStoreCreateRequest(Provider, Key, Name, Material(), []));
        Assert.Throws<ArgumentException>(() => new KeyStoreCreateRequest(Provider, Key, Name, Meta(), []));
        Assert.Throws<ArgumentException>(() => new KeyStoreCreateRequest(Provider, Key, Name, Meta(), [
            KeyStoreMaterialChange.Upsert(Ref(2), Material())]));
        Assert.Throws<ArgumentException>(() => new KeyStoreReplaceRequest(Provider, Key, new KeyStoreRevision(1), Material(), []));
        Assert.Throws<ArgumentException>(() => new KeyStoreCreateRequest(Provider, Key, Name, Meta(), [
            KeyStoreMaterialChange.Upsert(Ref(1, OtherProvider), Material())]));
        Assert.Throws<ArgumentException>(() => new KeyStoreCreateRequest(Provider, Key, Name, Meta(), [
            KeyStoreMaterialChange.Delete(Ref(1))]));
        Assert.Throws<ArgumentException>(() => new KeyStoreReplaceRequest(Provider, Key, new KeyStoreRevision(1), Meta(), [
            KeyStoreMaterialChange.Delete(Ref(1)), KeyStoreMaterialChange.Upsert(Ref(1), Material())]));
        Assert.Throws<ArgumentException>(() => KeyStoreMaterialChange.Upsert(Ref(1), Meta()));
        Assert.Throws<ArgumentException>(() => new KeyStoreEntry(Provider, Key, Name, new KeyStoreRevision(1), Material()));
        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyStoreRevision(0));
        Assert.Throws<ArgumentException>(() => new NonceRangeReservation(default, 0, 0, 1));
    }

    [Test]
    public void MaterialBatchRejectsOversizedOperations()
    {
        List<KeyStoreMaterialChange> changes = Enumerable.Range(1, 129)
            .Select(i => KeyStoreMaterialChange.Upsert(Ref(i), Material())).ToList();
        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyStoreReplaceRequest(Provider,
            Key, new KeyStoreRevision(1), Meta(), changes));
    }

    [Test]
    public void ProtectionContextBindsIdentityRevisionAndExactVersion()
    {
        byte[] baseline = KeyStoreProtectionContext.ForMetadata(Provider, Key, new KeyStoreRevision(1));
        byte[] newer = KeyStoreProtectionContext.ForMetadata(Provider, Key, new KeyStoreRevision(2));
        Assert.That(baseline, Is.Not.EqualTo(newer));
        Assert.That(baseline, Is.Not.EqualTo(KeyStoreProtectionContext.ForMetadata(OtherProvider, Key,
            new KeyStoreRevision(1))));
        Assert.That(KeyStoreProtectionContext.ForKeyMaterial(Ref(1)),
            Is.Not.EqualTo(KeyStoreProtectionContext.ForKeyMaterial(Ref(2))));
        Assert.That(KeyStoreProtectionContext.ForKeyMaterial(Ref(1)), Is.Not.EqualTo(baseline));
        Assert.Throws<ArgumentException>(() => KeyStoreProtectionContext.ForKeyMaterial(default));
    }

    [Test]
    public void MutationRequestsSnapshotTheirChangeCollections()
    {
        List<KeyStoreMaterialChange> changes = [KeyStoreMaterialChange.Upsert(Ref(1), Material())];
        KeyStoreCreateRequest create = new(Provider, Key, Name, Meta(), changes);
        changes.Clear();
        Assert.That(create.InitialMaterial.Count, Is.EqualTo(1));
        Assert.Throws<NotSupportedException>(() => ((IList<KeyStoreMaterialChange>)create.InitialMaterial).Clear());
    }

    [Test]
    public void StoreResultsRejectIncoherentSuccessOrRejection()
    {
        Assert.That(KeyStoreMutationResult.Written(new KeyStoreRevision(1)).Revision!.Value.Value, Is.EqualTo(1));
        Assert.That(KeyStoreMutationResult.Deleted().Revision, Is.Null);
        Assert.That(KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.RevisionMismatch).Revision, Is.Null);
        Assert.Throws<ArgumentException>(() => KeyStoreMutationResult.Written(default));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.Applied));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeyStoreMaterialReadResult.Rejected(KeyStoreMaterialReadStatus.Found));
        Assert.Throws<ArgumentException>(() => KeyStoreMaterialReadResult.Found(Meta()));
    }

    [Test]
    public async Task AtomicCreateAllowsExactlyOneNameWinnerAcrossConcurrentCallers()
    {
        MemoryStore store = new();
        Task<KeyStoreMutationResult>[] tasks = Enumerable.Range(1, 32)
            .Select(i => Task.Run(async () => await store.TryCreateAsync(Create(
                new KeyId(GuidFromIndex(i)), Name)))).ToArray();
        KeyStoreMutationResult[] outcomes = await Task.WhenAll(tasks);
        Assert.That(outcomes.Count(r => r.Status == KeyStoreMutationStatus.Applied), Is.EqualTo(1));
        Assert.That(outcomes.Count(r => r.Status == KeyStoreMutationStatus.NameTaken), Is.EqualTo(31));
        KeyStoreEntry? winner = await store.FindByNameAsync(Provider, Name);
        Assert.That(winner, Is.Not.Null);
        Assert.That(winner!.Revision, Is.EqualTo(new KeyStoreRevision(1)));
        Assert.That((await store.FindByIdAsync(Provider, winner.KeyId))!.Name, Is.EqualTo(Name));
    }

    [Test]
    public async Task ReplaceCommitsMetadataAndVersionMaterialWithCas()
    {
        MemoryStore store = new();
        Assert.That((await store.TryCreateAsync(Create())).Status, Is.EqualTo(KeyStoreMutationStatus.Applied));
        KeyStoreReplaceRequest change = new(Provider, Key, new KeyStoreRevision(1), Meta(2), [
            KeyStoreMaterialChange.Delete(Ref(1)), KeyStoreMaterialChange.Upsert(Ref(2), Material(8))]);
        KeyStoreMutationResult outcome = await store.TryReplaceAsync(change);
        Assert.That(outcome.Status, Is.EqualTo(KeyStoreMutationStatus.Applied));
        Assert.That(outcome.Revision, Is.EqualTo(new KeyStoreRevision(2)));
        Assert.That((await store.ReadMaterialAsync(Ref(1), new KeyStoreRevision(2))).Status,
            Is.EqualTo(KeyStoreMaterialReadStatus.NotFound));
        Assert.That((await store.ReadMaterialAsync(Ref(2), new KeyStoreRevision(1))).Status,
            Is.EqualTo(KeyStoreMaterialReadStatus.RevisionMismatch));
        Assert.That((await store.ReadMaterialAsync(Ref(2), new KeyStoreRevision(2))).ProtectedMaterial!
            .ExportEncodedCopy(), Is.EqualTo(new byte[] { 8 }));
        Assert.That((await store.FindByNameAsync(Provider, Name))!.ProtectedMetadata.ExportEncodedCopy(),
            Is.EqualTo(new byte[] { 2 }));
        Assert.That((await store.TryReplaceAsync(change)).Status, Is.EqualTo(KeyStoreMutationStatus.RevisionMismatch));
    }

    [Test]
    public async Task ConcurrentReplacementsWithSameRevisionAllowOneWinner()
    {
        MemoryStore store = new();
        await store.TryCreateAsync(Create());
        Task<KeyStoreMutationResult>[] tasks = Enumerable.Range(1, 24).Select(i => Task.Run(async () =>
            await store.TryReplaceAsync(new KeyStoreReplaceRequest(Provider, Key,
                new KeyStoreRevision(1), Meta((byte)i), [])))).ToArray();
        KeyStoreMutationResult[] outcomes = await Task.WhenAll(tasks);
        Assert.That(outcomes.Count(r => r.Status == KeyStoreMutationStatus.Applied), Is.EqualTo(1));
        Assert.That(outcomes.Count(r => r.Status == KeyStoreMutationStatus.RevisionMismatch), Is.EqualTo(23));
        Assert.That((await store.FindByIdAsync(Provider, Key))!.Revision.Value, Is.EqualTo(2));
    }

    [Test]
    public async Task CancellationBeforeCommitHasNoEffectsInReferenceStore()
    {
        MemoryStore store = new();
        using CancellationTokenSource source = new();
        source.Cancel();
        Assert.ThrowsAsync<OperationCanceledException>(async () => await store.TryCreateAsync(
            Create(), source.Token));
        Assert.That(await store.FindByNameAsync(Provider, Name), Is.Null);
    }

    [Test]
    public async Task DeleteAtomicallyFreesNameAndAllVersions()
    {
        MemoryStore store = new();
        await store.TryCreateAsync(Create());
        Assert.That((await store.TryDeleteAsync(Provider, Key, new KeyStoreRevision(10))).Status,
            Is.EqualTo(KeyStoreMutationStatus.RevisionMismatch));
        Assert.That((await store.FindByNameAsync(Provider, Name)), Is.Not.Null);
        Assert.That((await store.TryDeleteAsync(Provider, Key, new KeyStoreRevision(1))).Status,
            Is.EqualTo(KeyStoreMutationStatus.Applied));
        Assert.That(await store.FindByNameAsync(Provider, Name), Is.Null);
        Assert.That((await store.ReadMaterialAsync(Ref(1), new KeyStoreRevision(1))).Status,
            Is.EqualTo(KeyStoreMaterialReadStatus.NotFound));
        Assert.That((await store.TryCreateAsync(Create(OtherKey))).Status, Is.EqualTo(KeyStoreMutationStatus.Applied));
        Assert.That((await store.TryCreateAsync(Create(Key, new KeyName("OtherName")))).Status,
            Is.EqualTo(KeyStoreMutationStatus.KeyAlreadyExists));
    }

    [Test]
    public void NonceRangesRejectOverflowAndRemainExactKeyScoped()
    {
        NonceRangeReservation a = new(Ref(1), 42, 10, 4);
        Assert.Multiple(() =>
        {
            Assert.That(a.EndExclusive, Is.EqualTo(14UL));
            Assert.That(a.Reference, Is.EqualTo(Ref(1)));
            Assert.That(a.Prefix, Is.EqualTo(42u));
        });
        Assert.Throws<ArgumentException>(() => new NonceRangeReservation(Ref(1), 42, ulong.MaxValue, 1));
        Assert.Throws<ArgumentException>(() => new NonceRangeReservation(Ref(1), 42, 10, 0));
    }

    [Test]
    public void ExternalProtectorContractKeepsRootSecretPrivate()
    {
        IKeyStoreProtector protector = new ContractOnlyProtector();
        Assert.That(protector.CurrentReference, Is.EqualTo(Protector));
        Assert.That(typeof(IKeyStoreProtector).GetMethods().Any(method =>
            method.ReturnType == typeof(byte[]) || method.ReturnType == typeof(ReadOnlyMemory<byte>)), Is.False);
        using SensitiveMaterialLease secret = SensitiveMaterialLease.CreateCopy([1, 2, 3]);
        Assert.ThrowsAsync<NotSupportedException>(async () =>
            await protector.ProtectAsync(secret, ProtectionPurpose.KeyMaterial, new byte[] { 9 }));
    }

    private static Guid GuidFromIndex(int index)
    {
        byte[] bytes = new byte[16];
        bytes[0] = (byte)index;
        bytes[7] = 0x40;
        bytes[8] = 0x80;
        return new Guid(bytes);
    }

    private sealed class ContractOnlyProtector : IKeyStoreProtector
    {
        public ProtectorReference CurrentReference => Protector;

        public ValueTask<ProtectedStoreEnvelope> ProtectAsync(SensitiveMaterialLease plaintext,
            ProtectionPurpose purpose, ReadOnlyMemory<byte> authenticatedContext,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public ValueTask<SensitiveMaterialLease> UnprotectAsync(ProtectedStoreEnvelope envelope,
            ProtectionPurpose expectedPurpose, ReadOnlyMemory<byte> authenticatedContext,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    /// <summary>Test double only: lock simulates the cross-process linearization requirement.</summary>
    internal sealed class MemoryStore : IKeyStore
    {
        private readonly object _gate = new();
        private readonly Dictionary<(ProviderId, KeyId), Stored> _records = new();
        private readonly Dictionary<(ProviderId, KeyName), KeyId> _names = new();
        private readonly HashSet<(ProviderId, KeyId)> _usedIds = new();

        public KeyStoreCapabilities Capabilities { get; } = new(false);

        public ValueTask<KeyStoreEntry?> FindByNameAsync(ProviderId providerId, KeyName name,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                return ValueTask.FromResult(_names.TryGetValue((providerId, name), out KeyId id)
                    ? _records[(providerId, id)].Entry : null);
            }
        }

        public ValueTask<KeyStoreEntry?> FindByIdAsync(ProviderId providerId, KeyId keyId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                return ValueTask.FromResult(_records.TryGetValue((providerId, keyId), out Stored? stored)
                    ? stored.Entry : null);
            }
        }

        public ValueTask<KeyStoreMaterialReadResult> ReadMaterialAsync(KeyReference reference,
            KeyStoreRevision expectedRevision, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (!_records.TryGetValue((reference.ProviderId, reference.KeyId), out Stored? stored))
                {
                    return ValueTask.FromResult(KeyStoreMaterialReadResult.Rejected(KeyStoreMaterialReadStatus.NotFound));
                }

                if (stored.Entry.Revision != expectedRevision)
                {
                    return ValueTask.FromResult(KeyStoreMaterialReadResult.Rejected(KeyStoreMaterialReadStatus.RevisionMismatch));
                }

                return ValueTask.FromResult(stored.Materials.TryGetValue(reference.Version, out ProtectedStoreEnvelope? material)
                    ? KeyStoreMaterialReadResult.Found(material)
                    : KeyStoreMaterialReadResult.Rejected(KeyStoreMaterialReadStatus.NotFound));
            }
        }

        public ValueTask<KeyStoreMutationResult> TryCreateAsync(KeyStoreCreateRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_names.ContainsKey((request.ProviderId, request.Name)))
                {
                    return ValueTask.FromResult(KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.NameTaken));
                }

                if (_usedIds.Contains((request.ProviderId, request.KeyId)))
                {
                    return ValueTask.FromResult(KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.KeyAlreadyExists));
                }

                KeyStoreRevision revision = new(1);
                Stored stored = new(new KeyStoreEntry(request.ProviderId, request.KeyId,
                    request.Name, revision, request.ProtectedMetadata));
                foreach (KeyStoreMaterialChange change in request.InitialMaterial)
                {
                    stored.Materials.Add(change.Reference.Version, change.Material!);
                }

                _records.Add((request.ProviderId, request.KeyId), stored);
                _usedIds.Add((request.ProviderId, request.KeyId));
                _names.Add((request.ProviderId, request.Name), request.KeyId);
                return ValueTask.FromResult(KeyStoreMutationResult.Written(revision));
            }
        }

        public ValueTask<KeyStoreMutationResult> TryReplaceAsync(KeyStoreReplaceRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (!_records.TryGetValue((request.ProviderId, request.KeyId), out Stored? stored))
                {
                    return ValueTask.FromResult(KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.NotFound));
                }

                if (stored.Entry.Revision != request.ExpectedRevision)
                {
                    return ValueTask.FromResult(KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.RevisionMismatch));
                }

                KeyStoreRevision next = new(checked(stored.Entry.Revision.Value + 1));
                Dictionary<KeyVersion, ProtectedStoreEnvelope> materials = new(stored.Materials);
                foreach (KeyStoreMaterialChange change in request.MaterialChanges)
                {
                    if (change.IsDelete)
                    {
                        materials.Remove(change.Reference.Version);
                    }
                    else
                    {
                        materials[change.Reference.Version] = change.Material!;
                    }
                }

                _records[(request.ProviderId, request.KeyId)] = new Stored(
                    new KeyStoreEntry(request.ProviderId, request.KeyId, stored.Entry.Name,
                        next, request.ProtectedMetadata), materials);
                return ValueTask.FromResult(KeyStoreMutationResult.Written(next));
            }
        }

        public ValueTask<KeyStoreMutationResult> TryDeleteAsync(ProviderId providerId, KeyId keyId,
            KeyStoreRevision expectedRevision, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (!_records.TryGetValue((providerId, keyId), out Stored? stored))
                {
                    return ValueTask.FromResult(KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.NotFound));
                }

                if (stored.Entry.Revision != expectedRevision)
                {
                    return ValueTask.FromResult(KeyStoreMutationResult.Rejected(KeyStoreMutationStatus.RevisionMismatch));
                }

                _records.Remove((providerId, keyId));
                _names.Remove((providerId, stored.Entry.Name));
                return ValueTask.FromResult(KeyStoreMutationResult.Deleted());
            }
        }

        private sealed class Stored
        {
            public Stored(KeyStoreEntry entry, Dictionary<KeyVersion, ProtectedStoreEnvelope>? materials = null)
            {
                Entry = entry;
                Materials = materials ?? new();
            }

            public KeyStoreEntry Entry { get; }

            public Dictionary<KeyVersion, ProtectedStoreEnvelope> Materials { get; }
        }
    }
}
