using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Protection;
using Laveyana.Security.Software;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Re-protection fault injection against an atomic in-memory test store, not production durability proof.</summary>
[TestFixture]
internal sealed class SoftwareKeyReprotectionTests
{
    private static readonly ProviderId Provider = ProviderId.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly KeyName Name = new("Reprotected");

    private static ProtectorGenerationRouter Router(IKeyStoreProtector current, IKeyStoreProtector old,
        HistoricalProtectorStatus status = HistoricalProtectorStatus.LegacyReadOnly) =>
        new(current, [new HistoricalProtectorRegistration(old, status)]);

    private static async Task<LogicalKeyHandle> Create(StorageContractsTests.MemoryStore store,
        IKeyStoreProtector protector)
    {
        SoftwareKeyProviderBackend backend = new(Provider, store, protector);
        KeyDescriptor descriptor = await backend.CreateAsync(Name, WellKnownAlgorithms.HmacSha256,
            [WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac]);
        return new LogicalKeyHandle(Provider, descriptor.KeyId);
    }

    private static async Task<byte[]> ReadMaterial(IKeyStore store, IKeyStoreProtector protector,
        LogicalKeyHandle handle, KeyVersion version)
    {
        KeyStoreEntry entry = (await store.FindByIdAsync(Provider, handle.KeyId))!;
        KeyReference reference = new(Provider, handle.KeyId, version);
        ProtectedStoreEnvelope envelope = (await store.ReadMaterialAsync(reference, entry.Revision)).ProtectedMaterial!;
        using SensitiveMaterialLease lease = await protector.UnprotectAsync(envelope,
            ProtectionPurpose.KeyMaterial, KeyStoreProtectionContext.ForKeyMaterial(reference));
        byte[]? copy = null;
        lease.UseMaterial(bytes => copy = bytes.ToArray());
        return copy!;
    }

    [Test]
    public async Task MigratesEveryLiveVersionWithoutChangingKeyReferencesOrSecretMaterial()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector old = new(1);
        using SoftwareKeyProviderTests.TestProtector current = new(2);
        LogicalKeyHandle handle = await Create(store, old);
        SoftwareKeyProviderBackend backend = new(Provider, store, old);
        await backend.RotateAsync(handle);
        KeyVersionDescriptor pending = await backend.CreateVersionAsync(handle);
        byte[] originalV1 = await ReadMaterial(store, old, handle, new KeyVersion(1));
        byte[] originalV2 = await ReadMaterial(store, old, handle, new KeyVersion(2));
        byte[] originalV3 = await ReadMaterial(store, old, handle, pending.Reference.Version);
        KeyStoreEntry entryBefore = (await store.FindByIdAsync(Provider, handle.KeyId))!;
        ProtectorGenerationRouter router = Router(current, old);
        SoftwareKeyReprotectionService service = new(Provider, store, router);
        KeyReprotectionResult result = await service.ReprotectAsync(handle);
        Assert.That(result.Status, Is.EqualTo(KeyReprotectionStatus.Reprotected));
        Assert.That(result.Revision.Value, Is.EqualTo(entryBefore.Revision.Value + 1));
        KeyStoreEntry after = (await store.FindByIdAsync(Provider, handle.KeyId))!;
        Assert.That(after.Name, Is.EqualTo(entryBefore.Name));
        Assert.That(after.ProtectedMetadata.Protector, Is.EqualTo(current.CurrentReference));
        foreach (int i in new[] { 1, 2, 3 })
        {
            KeyReference reference = new(Provider, handle.KeyId, new KeyVersion(i));
            Assert.That((await store.ReadMaterialAsync(reference, after.Revision)).ProtectedMaterial!.Protector,
                Is.EqualTo(current.CurrentReference));
        }

        Assert.That(await ReadMaterial(store, router, handle, new KeyVersion(1)), Is.EqualTo(originalV1));
        Assert.That(await ReadMaterial(store, router, handle, new KeyVersion(2)), Is.EqualTo(originalV2));
        Assert.That(await ReadMaterial(store, router, handle, pending.Reference.Version), Is.EqualTo(originalV3));
        SoftwareKeyProviderBackend migrated = new(Provider, store, router);
        Assert.That((await migrated.FindLogicalAsync(handle))!.ActiveVersion, Is.EqualTo(new KeyVersion(2)));
        Assert.That((await migrated.FindExactAsync(handle.AtVersion(pending.Reference.Version)))!.State,
            Is.EqualTo(KeyVersionState.Pending));
        CryptographicOperations.ZeroMemory(originalV1);
        CryptographicOperations.ZeroMemory(originalV2);
        CryptographicOperations.ZeroMemory(originalV3);
    }

    [Test]
    public async Task NoOpIsAuthenticatedAndDoesNotIncrementRevision()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector old = new(1);
        using SoftwareKeyProviderTests.TestProtector current = new(2);
        LogicalKeyHandle handle = await Create(store, old);
        SoftwareKeyReprotectionService service = new(Provider, store, Router(current, old));
        await service.ReprotectAsync(handle);
        KeyStoreEntry before = (await store.FindByIdAsync(Provider, handle.KeyId))!;
        KeyReprotectionResult result = await service.ReprotectAsync(handle);
        Assert.That(result.Status, Is.EqualTo(KeyReprotectionStatus.AlreadyCurrent));
        Assert.That(result.Revision, Is.EqualTo(before.Revision));
    }

    [Test]
    public async Task CompromisedGenerationMustNotBeSilentlyRewrapped()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector old = new(1);
        using SoftwareKeyProviderTests.TestProtector current = new(2);
        LogicalKeyHandle handle = await Create(store, old);
        ProtectorGenerationRouter router = Router(current, old, HistoricalProtectorStatus.Compromised);
        Assert.That(router.Classify(old.CurrentReference), Is.EqualTo(ProtectorGenerationClassification.Compromised));
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await new SoftwareKeyReprotectionService(Provider, store, router).ReprotectAsync(handle));
        Assert.That((await store.FindByIdAsync(Provider, handle.KeyId))!.Revision.Value, Is.EqualTo(1));
    }

    [Test]
    public async Task UnknownGenerationAndWrongHistoricalKeyFailWithoutCommit()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector old = new(1);
        using SoftwareKeyProviderTests.TestProtector impostor = new(1);
        using SoftwareKeyProviderTests.TestProtector current = new(2);
        LogicalKeyHandle handle = await Create(store, old);
        SoftwareKeyReprotectionService unknown = new(Provider, store, new ProtectorGenerationRouter(current, []));
        Assert.ThrowsAsync<CryptographicException>(async () => await unknown.ReprotectAsync(handle));
        SoftwareKeyReprotectionService forged = new(Provider, store, Router(current, impostor));
        Assert.CatchAsync<CryptographicException>((Func<Task>)(async () => await forged.ReprotectAsync(handle)));
        Assert.That((await store.FindByIdAsync(Provider, handle.KeyId))!.Revision.Value, Is.EqualTo(1));
    }

    [Test]
    public async Task BrokenNewProtectorIsRejectedBeforeAnyCommit()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector old = new(1);
        using SoftwareKeyProviderTests.TestProtector newImplementation = new(2);
        LogicalKeyHandle handle = await Create(store, old);
        FaultyNewProtector broken = new(newImplementation);
        SoftwareKeyReprotectionService migration = new(Provider, store, Router(broken, old));
        Assert.CatchAsync<CryptographicException>((Func<Task>)(async () => await migration.ReprotectAsync(handle)));
        KeyStoreEntry entry = (await store.FindByIdAsync(Provider, handle.KeyId))!;
        Assert.That(entry.Revision.Value, Is.EqualTo(1));
        Assert.That(entry.ProtectedMetadata.Protector, Is.EqualTo(old.CurrentReference));
    }

    [Test]
    public async Task FailedCommitPreservesOldEnvelopeAndCanBeRetriedAfterReconciliation()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector old = new(1);
        using SoftwareKeyProviderTests.TestProtector current = new(2);
        LogicalKeyHandle handle = await Create(store, old);
        FaultStore fault = new(store) { FailBeforeReplace = true };
        SoftwareKeyReprotectionService service = new(Provider, fault, Router(current, old));
        Assert.ThrowsAsync<SoftwareKeyCommitUncertainException>(async () => await service.ReprotectAsync(handle));
        KeyStoreEntry afterFailure = (await store.FindByIdAsync(Provider, handle.KeyId))!;
        Assert.That(afterFailure.Revision.Value, Is.EqualTo(1));
        Assert.That(afterFailure.ProtectedMetadata.Protector, Is.EqualTo(old.CurrentReference));
        // A fresh authoritative read establishes that the simulated pre-commit failure did not commit.
        Assert.That((await service.ReprotectAsync(handle)).Status, Is.EqualTo(KeyReprotectionStatus.Reprotected));
    }

    [Test]
    public async Task PostCommitFailureIsUncertainButAtomicAndReconciliationSeesCurrentState()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector old = new(1);
        using SoftwareKeyProviderTests.TestProtector current = new(2);
        LogicalKeyHandle handle = await Create(store, old);
        FaultStore fault = new(store) { FailAfterReplace = true };
        SoftwareKeyReprotectionService service = new(Provider, fault, Router(current, old));
        Assert.ThrowsAsync<SoftwareKeyCommitUncertainException>(async () => await service.ReprotectAsync(handle));
        KeyStoreEntry committed = (await store.FindByIdAsync(Provider, handle.KeyId))!;
        Assert.That(committed.Revision.Value, Is.EqualTo(2));
        Assert.That(committed.ProtectedMetadata.Protector, Is.EqualTo(current.CurrentReference));
        Assert.That((await store.ReadMaterialAsync(new KeyReference(Provider, handle.KeyId, new KeyVersion(1)),
            committed.Revision)).ProtectedMaterial!.Protector, Is.EqualTo(current.CurrentReference));
        Assert.That((await service.ReprotectAsync(handle)).Status, Is.EqualTo(KeyReprotectionStatus.AlreadyCurrent));
    }

    [Test]
    public async Task StaleMigrationGetsDefinitiveCasConflict()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector old = new(1);
        using SoftwareKeyProviderTests.TestProtector current = new(2);
        LogicalKeyHandle handle = await Create(store, old);
        SoftwareKeyProviderTests.BarrierStore gate = new(store) { GateFirstTwoReplaces = true };
        SoftwareKeyReprotectionService service = new(Provider, gate, Router(current, old));
        Task<KeyReprotectionResult> first = Task.Run(async () => await service.ReprotectAsync(handle));
        Task<KeyReprotectionResult> second = Task.Run(async () => await service.ReprotectAsync(handle));
        await Task.WhenAll(first.ContinueWith(_ => { }), second.ContinueWith(_ => { }))
            .WaitAsync(TimeSpan.FromSeconds(15));
        Assert.That(new[] { first, second }.Count(x => x.IsCompletedSuccessfully), Is.EqualTo(1));
        Assert.That(new[] { first, second }.Count(x => x.Exception?.GetBaseException() is SoftwareKeyConflictException),
            Is.EqualTo(1));
    }

    [Test]
    public async Task MixedGenerationsCanBeRepairedAtomically()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector old = new(1);
        using SoftwareKeyProviderTests.TestProtector current = new(2);
        LogicalKeyHandle handle = await Create(store, old);
        KeyStoreEntry before = (await store.FindByIdAsync(Provider, handle.KeyId))!;
        using SensitiveMaterialLease original = await old.UnprotectAsync(before.ProtectedMetadata,
            ProtectionPurpose.Metadata, KeyStoreProtectionContext.ForMetadata(Provider, handle.KeyId, before.Revision));
        KeyStoreRevision revision2 = new(2);
        ProtectedStoreEnvelope newMetadata = await current.ProtectAsync(original, ProtectionPurpose.Metadata,
            KeyStoreProtectionContext.ForMetadata(Provider, handle.KeyId, revision2));
        Assert.That((await store.TryReplaceAsync(new KeyStoreReplaceRequest(Provider, handle.KeyId,
            before.Revision, newMetadata, []))).Status, Is.EqualTo(KeyStoreMutationStatus.Applied));
        SoftwareKeyReprotectionService service = new(Provider, store, Router(current, old));
        Assert.That((await service.ReprotectAsync(handle)).Revision.Value, Is.EqualTo(3));
        KeyStoreEntry repaired = (await store.FindByIdAsync(Provider, handle.KeyId))!;
        Assert.That(repaired.ProtectedMetadata.Protector, Is.EqualTo(current.CurrentReference));
        Assert.That((await store.ReadMaterialAsync(new KeyReference(Provider, handle.KeyId, new KeyVersion(1)),
            repaired.Revision)).ProtectedMaterial!.Protector, Is.EqualTo(current.CurrentReference));
    }

    [Test]
    public async Task CancelledBeforeCommitDoesNotReplaceAnything()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector old = new(1);
        using SoftwareKeyProviderTests.TestProtector current = new(2);
        LogicalKeyHandle handle = await Create(store, old);
        using CancellationTokenSource cts = new();
        cts.Cancel();
        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await new SoftwareKeyReprotectionService(Provider, store, Router(current, old))
                .ReprotectAsync(handle, cts.Token));
        Assert.That((await store.FindByIdAsync(Provider, handle.KeyId))!.Revision.Value, Is.EqualTo(1));
    }

    [Test]
    public void RouterRejectsDuplicateAndInvalidGenerations()
    {
        using SoftwareKeyProviderTests.TestProtector old = new(1);
        using SoftwareKeyProviderTests.TestProtector current = new(2);
        Assert.Throws<ArgumentException>(() => new ProtectorGenerationRouter(current,
            [new HistoricalProtectorRegistration(old, HistoricalProtectorStatus.LegacyReadOnly),
                new HistoricalProtectorRegistration(old, HistoricalProtectorStatus.LegacyReadOnly)]));
        Assert.Throws<ArgumentException>(() => new ProtectorGenerationRouter(current,
            [new HistoricalProtectorRegistration(current, HistoricalProtectorStatus.LegacyReadOnly)]));
        Assert.That(Router(current, old).Classify(new ProtectorReference("Missing", 999)),
            Is.EqualTo(ProtectorGenerationClassification.Unknown));
    }

    [Test]
    public async Task RouterWritesOnlyCurrentAndNeverUsesHistoricalForEncryption()
    {
        using SoftwareKeyProviderTests.TestProtector old = new(1);
        using SoftwareKeyProviderTests.TestProtector current = new(2);
        ProtectorGenerationRouter router = Router(current, old);
        using SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy(new byte[32]);
        ProtectedStoreEnvelope envelope = await router.ProtectAsync(lease, ProtectionPurpose.KeyMaterial, new byte[] { 3, 4 });
        Assert.That(envelope.Protector, Is.EqualTo(current.CurrentReference));
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await old.UnprotectAsync(envelope, ProtectionPurpose.KeyMaterial, new byte[] { 3, 4 }));
    }

    private sealed class FaultyNewProtector(IKeyStoreProtector inner) : IKeyStoreProtector
    {
        public ProtectorReference CurrentReference => inner.CurrentReference;

        public async ValueTask<ProtectedStoreEnvelope> ProtectAsync(SensitiveMaterialLease plaintext,
            ProtectionPurpose purpose, ReadOnlyMemory<byte> context, CancellationToken cancellationToken = default)
        {
            ProtectedStoreEnvelope envelope = await inner.ProtectAsync(plaintext, purpose, context, cancellationToken);
            byte[] ciphertext = envelope.ExportEncodedCopy();
            ciphertext[^1] ^= 0x01;
            return new ProtectedStoreEnvelope(CurrentReference, purpose, ciphertext);
        }

        public ValueTask<SensitiveMaterialLease> UnprotectAsync(ProtectedStoreEnvelope envelope,
            ProtectionPurpose purpose, ReadOnlyMemory<byte> context, CancellationToken cancellationToken = default) =>
            inner.UnprotectAsync(envelope, purpose, context, cancellationToken);
    }

    private sealed class FaultStore(IKeyStore inner) : IKeyStore
    {
        public bool FailBeforeReplace { get; set; }
        public bool FailAfterReplace { get; set; }
        public KeyStoreCapabilities Capabilities => inner.Capabilities;
        public ValueTask<KeyStoreEntry?> FindByNameAsync(ProviderId p, KeyName n, CancellationToken c = default) =>
            inner.FindByNameAsync(p, n, c);
        public ValueTask<KeyStoreEntry?> FindByIdAsync(ProviderId p, KeyId k, CancellationToken c = default) =>
            inner.FindByIdAsync(p, k, c);
        public ValueTask<KeyStoreMaterialReadResult> ReadMaterialAsync(KeyReference r, KeyStoreRevision rev,
            CancellationToken c = default) => inner.ReadMaterialAsync(r, rev, c);
        public ValueTask<KeyStoreMutationResult> TryCreateAsync(KeyStoreCreateRequest r, CancellationToken c = default) =>
            inner.TryCreateAsync(r, c);
        public async ValueTask<KeyStoreMutationResult> TryReplaceAsync(KeyStoreReplaceRequest r,
            CancellationToken c = default)
        {
            if (FailBeforeReplace)
            {
                FailBeforeReplace = false;
                throw new IOException("Before simulated commit.");
            }

            KeyStoreMutationResult result = await inner.TryReplaceAsync(r, c);
            if (FailAfterReplace)
            {
                FailAfterReplace = false;
                throw new IOException("After simulated commit.");
            }

            return result;
        }
        public ValueTask<KeyStoreMutationResult> TryDeleteAsync(ProviderId p, KeyId k, KeyStoreRevision r,
            CancellationToken c = default) => inner.TryDeleteAsync(p, k, r, c);
    }
}
