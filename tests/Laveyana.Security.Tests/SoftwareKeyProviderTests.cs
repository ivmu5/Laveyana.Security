using System.Security.Cryptography;
using System.Text;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Software;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Operational smoke, concurrency and fault-injection tests; fake components are not production stores.</summary>
[TestFixture]
internal sealed class SoftwareKeyProviderTests
{
    private static readonly ProviderId Provider = ProviderId.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly KeyName Name = new("Master");
    private static readonly AlgorithmId Algorithm = WellKnownAlgorithms.HmacSha256;
    private static readonly CapabilityId[] Abilities = [WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac];

    private static SoftwareKeyProviderBackend CreateBackend(IKeyStore store, IKeyStoreProtector protector) =>
        new(Provider, store, protector);

    private static LogicalKeyHandle Handle(KeyDescriptor descriptor) =>
        new(descriptor.ProviderId, descriptor.KeyId);

    [Test]
    public async Task CreateReadsAuthenticatedMetadataAndExactMaterial()
    {
        StorageContractsTests.MemoryStore store = new();
        using TestProtector protector = new();
        SoftwareKeyProviderBackend backend = CreateBackend(store, protector);
        KeyDescriptor created = await backend.CreateAsync(Name, Algorithm, Abilities);
        Assert.That(created.State, Is.EqualTo(LogicalKeyState.Active));
        Assert.That(created.ActiveVersion, Is.EqualTo(new KeyVersion(1)));
        Assert.That((await backend.FindByNameAsync(Name))!.KeyId, Is.EqualTo(created.KeyId));
        Assert.That((await backend.FindLogicalAsync(Handle(created)))!.KeyId, Is.EqualTo(created.KeyId));
        KeyVersionDescriptor? exact = await backend.FindExactAsync(Handle(created).AtVersion(new KeyVersion(1)));
        Assert.That(exact!.State, Is.EqualTo(KeyVersionState.Active));
        Assert.That(exact.Capabilities, Is.EquivalentTo(Abilities));
        Assert.That(protector.ProtectedMaterialCount, Is.EqualTo(1));
        Assert.That(protector.LastMaterialWas32Bytes, Is.True);
        Assert.That((await backend.GetCapabilitiesAsync()).Supports(WellKnownCapabilities.Mac), Is.True);
    }

    [Test]
    public async Task GetOrCreateRaceProducesOneGenerationAndCleansAllLosers()
    {
        StorageContractsTests.MemoryStore store = new();
        using TestProtector protector = new();
        SoftwareKeyProviderBackend[] backends = Enumerable.Range(0, 24)
            .Select(_ => CreateBackend(store, protector)).ToArray();
        KeyDescriptor[] results = await Task.WhenAll(backends.Select(b => Task.Run(async () =>
            await b.GetOrCreateAsync(Name, Algorithm, Abilities))));
        Assert.That(results.Select(r => r.KeyId).Distinct().Count(), Is.EqualTo(1));
        Assert.That((await store.FindByNameAsync(Provider, Name))!.KeyId, Is.EqualTo(results[0].KeyId));
        Assert.That(protector.ProtectedMaterialCount, Is.GreaterThanOrEqualTo(1));
        Assert.That(protector.AllPlaintextLeasesDisposed, Is.True);
    }

    [Test]
    public async Task ProfileMismatchNeverReturnsWrongExistingKey()
    {
        StorageContractsTests.MemoryStore store = new();
        using TestProtector protector = new();
        SoftwareKeyProviderBackend backend = CreateBackend(store, protector);
        await backend.CreateAsync(Name, Algorithm, Abilities);
        Assert.ThrowsAsync<SoftwareKeyConflictException>(async () =>
            await backend.GetOrCreateAsync(Name, Algorithm, [WellKnownCapabilities.Mac]));
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await backend.CreateAsync(new KeyName("Wrong"), WellKnownAlgorithms.HmacSha1, Abilities));
        Assert.ThrowsAsync<ArgumentException>(async () =>
            await backend.CreateAsync(new KeyName("Wrong"), Algorithm, [WellKnownCapabilities.Encrypt]));
    }

    [Test]
    public async Task PendingActivationDiscardAndHighWaterMarkSurviveStoreReload()
    {
        StorageContractsTests.MemoryStore store = new();
        using TestProtector protector = new();
        SoftwareKeyProviderBackend backend = CreateBackend(store, protector);
        LogicalKeyHandle key = Handle(await backend.CreateAsync(Name, Algorithm, Abilities));
        KeyVersionDescriptor pending = await backend.CreateVersionAsync(key);
        Assert.That(pending.Reference.Version, Is.EqualTo(new KeyVersion(2)));
        Assert.That((await backend.FindLogicalAsync(key))!.ActiveVersion, Is.EqualTo(new KeyVersion(1)));
        await backend.DiscardAsync(key, new KeyVersion(2));
        Assert.That((await backend.FindExactAsync(key.AtVersion(new KeyVersion(2))))!.State,
            Is.EqualTo(KeyVersionState.Deleted));
        SoftwareKeyProviderBackend reloaded = CreateBackend(store, protector);
        KeyVersionDescriptor newPending = await reloaded.CreateVersionAsync(key);
        Assert.That(newPending.Reference.Version, Is.EqualTo(new KeyVersion(3)));
        KeyDescriptor active = await reloaded.ActivateAsync(key, new KeyVersion(3));
        Assert.That(active.ActiveVersion, Is.EqualTo(new KeyVersion(3)));
        Assert.That((await backend.FindExactAsync(key.AtVersion(new KeyVersion(1))))!.State,
            Is.EqualTo(KeyVersionState.Retired));
        Assert.That((await reloaded.FindExactAsync(key.AtVersion(new KeyVersion(3))))!.State,
            Is.EqualTo(KeyVersionState.Active));
    }

    [Test]
    public async Task RotateRetireDeleteAndAtomicNameReuse()
    {
        StorageContractsTests.MemoryStore store = new();
        using TestProtector protector = new();
        SoftwareKeyProviderBackend backend = CreateBackend(store, protector);
        KeyDescriptor initial = await backend.CreateAsync(Name, Algorithm, Abilities);
        LogicalKeyHandle handle = Handle(initial);
        KeyDescriptor rotated = await backend.RotateAsync(handle);
        Assert.That(rotated.ActiveVersion, Is.EqualTo(new KeyVersion(2)));
        Assert.That((await backend.FindExactAsync(handle.AtVersion(new KeyVersion(1))))!.State,
            Is.EqualTo(KeyVersionState.Retired));
        await backend.DeleteVersionAsync(handle, new KeyVersion(1), DateTimeOffset.UtcNow);
        Assert.That((await backend.FindExactAsync(handle.AtVersion(new KeyVersion(1))))!.State,
            Is.EqualTo(KeyVersionState.Deleted));
        Assert.That((await store.ReadMaterialAsync(new KeyReference(Provider, initial.KeyId, new KeyVersion(1)),
            (await store.FindByIdAsync(Provider, initial.KeyId))!.Revision)).Status,
            Is.EqualTo(KeyStoreMaterialReadStatus.NotFound));
        await backend.RetireAsync(handle);
        await backend.DeleteAsync(handle, DateTimeOffset.UtcNow);
        Assert.That(await backend.FindByNameAsync(Name), Is.Null);
        KeyDescriptor after = await backend.CreateAsync(Name, Algorithm, Abilities);
        Assert.That(after.KeyId, Is.Not.EqualTo(initial.KeyId));
    }

    [Test]
    public async Task ForceDeletesRequireExplicitPathsAndCannotDeleteActiveVersion()
    {
        StorageContractsTests.MemoryStore store = new();
        using TestProtector protector = new();
        SoftwareKeyProviderBackend backend = CreateBackend(store, protector);
        KeyDescriptor created = await backend.CreateAsync(Name, Algorithm, Abilities);
        LogicalKeyHandle handle = Handle(created);
        Assert.CatchAsync<InvalidOperationException>(async () =>
            await backend.DeleteAsync(handle, DateTimeOffset.UtcNow));
        Assert.CatchAsync<InvalidOperationException>(async () =>
            await backend.ForceDeleteVersionAsync(handle, new KeyVersion(1)));
        await backend.ForceDeleteAsync(handle);
        Assert.That(await backend.FindLogicalAsync(handle), Is.Null);
    }

    [Test]
    public async Task TwoStaleMutationsYieldOneWinnerAndDefinitiveConflict()
    {
        StorageContractsTests.MemoryStore memory = new();
        using TestProtector protector = new();
        BarrierStore store = new(memory) { GateFirstTwoReplaces = true };
        SoftwareKeyProviderBackend a = CreateBackend(store, protector);
        SoftwareKeyProviderBackend b = CreateBackend(store, protector);
        LogicalKeyHandle key = Handle(await a.CreateAsync(Name, Algorithm, Abilities));
        Task<KeyDescriptor> first = Task.Run(async () => await a.RotateAsync(key));
        Task<KeyDescriptor> second = Task.Run(async () => await b.RotateAsync(key));
        Task[] pair = [first.ContinueWith(_ => { }), second.ContinueWith(_ => { })];
        await Task.WhenAll(pair).WaitAsync(TimeSpan.FromSeconds(15));
        Assert.That(new[] { first, second }.Count(x => x.IsCompletedSuccessfully), Is.EqualTo(1));
        Assert.That(new[] { first, second }.Count(x => x.Exception?.GetBaseException() is SoftwareKeyConflictException),
            Is.EqualTo(1));
        Assert.That((await a.FindLogicalAsync(key))!.ActiveVersion, Is.EqualTo(new KeyVersion(2)));
    }

    [Test]
    public async Task PostCommitFailureMustNeverBlindlyRetryRotation()
    {
        StorageContractsTests.MemoryStore memory = new();
        using TestProtector protector = new();
        BarrierStore store = new(memory);
        SoftwareKeyProviderBackend backend = CreateBackend(store, protector);
        LogicalKeyHandle key = Handle(await backend.CreateAsync(Name, Algorithm, Abilities));
        store.ThrowAfterNextReplace = true;
        Assert.ThrowsAsync<SoftwareKeyCommitUncertainException>(async () => await backend.RotateAsync(key));
        Assert.That((await backend.FindLogicalAsync(key))!.ActiveVersion, Is.EqualTo(new KeyVersion(2)));
        Assert.That((await backend.FindExactAsync(key.AtVersion(new KeyVersion(3)))), Is.Null);
    }

    [Test]
    public async Task RetentionPersistsAcrossAdaptersAndBlocksNormalDeletion()
    {
        StorageContractsTests.MemoryStore store = new();
        using TestProtector protector = new();
        SoftwareKeyProviderBackend creator = CreateBackend(store, protector);
        SoftwareKeyRetention retention = new(new DateTimeOffset(2040, 1, 1, 0, 0, 0,
            TimeSpan.Zero), true);
        KeyDescriptor descriptor = await creator.CreateAsync(Name, Algorithm, Abilities, retention);
        LogicalKeyHandle key = Handle(descriptor);
        SoftwareKeyProviderBackend reloaded = CreateBackend(store, protector);
        Assert.That((await reloaded.GetOrCreateAsync(Name, Algorithm, Abilities, retention)).KeyId,
            Is.EqualTo(key.KeyId));
        Assert.ThrowsAsync<SoftwareKeyConflictException>(async () =>
            await reloaded.GetOrCreateAsync(Name, Algorithm, Abilities));
        await reloaded.RetireAsync(key);
        Assert.CatchAsync<InvalidOperationException>(async () =>
            await reloaded.DeleteAsync(key, DateTimeOffset.UtcNow));
        await reloaded.ForceDeleteAsync(key);
        Assert.That(await creator.FindByNameAsync(Name), Is.Null);
    }

    [Test]
    public async Task AmbiguousCreateDoesNotSilentlyProduceAnotherGeneration()
    {
        StorageContractsTests.MemoryStore memory = new();
        using TestProtector protector = new();
        BarrierStore store = new(memory) { ThrowAfterNextCreate = true };
        SoftwareKeyProviderBackend backend = CreateBackend(store, protector);
        Assert.ThrowsAsync<SoftwareKeyCommitUncertainException>(async () =>
            await backend.GetOrCreateAsync(Name, Algorithm, Abilities));
        KeyDescriptor? reconciled = await backend.FindByNameAsync(Name);
        Assert.That(reconciled, Is.Not.Null);
        Assert.That((await backend.GetOrCreateAsync(Name, Algorithm, Abilities)).KeyId,
            Is.EqualTo(reconciled!.KeyId));
    }

    [Test]
    public async Task CancelledBeforeMutationNeverClaimsName()
    {
        StorageContractsTests.MemoryStore memory = new();
        using TestProtector protector = new();
        SoftwareKeyProviderBackend backend = CreateBackend(memory, protector);
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        Assert.CatchAsync<OperationCanceledException>(async () =>
            await backend.CreateAsync(Name, Algorithm, Abilities, cancellation.Token));
        Assert.That(await memory.FindByNameAsync(Provider, Name), Is.Null);
    }

    [Test]
    public async Task WrongProviderAndAuthenticatedContextFailClosed()
    {
        StorageContractsTests.MemoryStore store = new();
        using TestProtector protector = new();
        SoftwareKeyProviderBackend backend = CreateBackend(store, protector);
        KeyDescriptor key = await backend.CreateAsync(Name, Algorithm, Abilities);
        LogicalKeyHandle foreign = new(ProviderId.New(), key.KeyId);
        Assert.ThrowsAsync<ArgumentException>(async () => await backend.FindLogicalAsync(foreign));
        KeyStoreEntry entry = (await store.FindByIdAsync(Provider, key.KeyId))!;
        Assert.CatchAsync<CryptographicException>(async () =>
        {
            using SensitiveMaterialLease _ = await protector.UnprotectAsync(entry.ProtectedMetadata,
                ProtectionPurpose.Metadata, KeyStoreProtectionContext.ForMetadata(Provider, key.KeyId,
                    new KeyStoreRevision(2)));
        });
    }

    internal sealed class BarrierStore(IKeyStore inner) : IKeyStore
    {
        private readonly Barrier _barrier = new(2);
        private int _intercepted;
        public bool GateFirstTwoReplaces { get; set; }
        public bool ThrowAfterNextReplace { get; set; }
        public bool ThrowAfterNextCreate { get; set; }
        public KeyStoreCapabilities Capabilities => inner.Capabilities;
        public ValueTask<KeyStoreEntry?> FindByNameAsync(ProviderId p, KeyName n, CancellationToken c = default) =>
            inner.FindByNameAsync(p, n, c);
        public ValueTask<KeyStoreEntry?> FindByIdAsync(ProviderId p, KeyId k, CancellationToken c = default) =>
            inner.FindByIdAsync(p, k, c);
        public ValueTask<KeyStoreMaterialReadResult> ReadMaterialAsync(KeyReference r, KeyStoreRevision v,
            CancellationToken c = default) => inner.ReadMaterialAsync(r, v, c);
        public async ValueTask<KeyStoreMutationResult> TryCreateAsync(KeyStoreCreateRequest r, CancellationToken c = default)
        {
            KeyStoreMutationResult result = await inner.TryCreateAsync(r, c);
            if (ThrowAfterNextCreate)
            {
                ThrowAfterNextCreate = false;
                throw new IOException("Injected failure after durable create");
            }

            return result;
        }
        public async ValueTask<KeyStoreMutationResult> TryReplaceAsync(KeyStoreReplaceRequest r, CancellationToken c = default)
        {
            if (GateFirstTwoReplaces && Interlocked.Increment(ref _intercepted) <= 2)
            {
                _barrier.SignalAndWait(TimeSpan.FromSeconds(10));
            }

            KeyStoreMutationResult result = await inner.TryReplaceAsync(r, c);
            if (ThrowAfterNextReplace)
            {
                ThrowAfterNextReplace = false;
                throw new IOException("Injected failure after durable commit");
            }

            return result;
        }
        public ValueTask<KeyStoreMutationResult> TryDeleteAsync(ProviderId p, KeyId k, KeyStoreRevision v,
            CancellationToken c = default) => inner.TryDeleteAsync(p, k, v, c);
    }

    /// <summary>Test-only AES-GCM protector that authenticates purpose, reference and context.</summary>
    internal sealed class TestProtector : IKeyStoreProtector, IDisposable
    {
        private readonly byte[] _root = RandomNumberGenerator.GetBytes(32);
        private readonly System.Collections.Concurrent.ConcurrentBag<SensitiveMaterialLease> _seenLeases = new();
        private int _materials;
        private int _was32;
        public TestProtector(int generation = 1) => CurrentReference = new ProtectorReference("TestOnly", generation);
        public ProtectorReference CurrentReference { get; }
        public int ProtectedMaterialCount => Volatile.Read(ref _materials);
        public bool LastMaterialWas32Bytes => Volatile.Read(ref _was32) == 1;
        public bool AllPlaintextLeasesDisposed => _seenLeases.All(lease =>
        {
            try
            {
                _ = lease.Length;
                return false;
            }
            catch (ObjectDisposedException)
            {
                return true;
            }
        });

        public ValueTask<ProtectedStoreEnvelope> ProtectAsync(SensitiveMaterialLease plaintext,
            ProtectionPurpose purpose, ReadOnlyMemory<byte> authenticatedContext,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _seenLeases.Add(plaintext);
            ProtectedStoreEnvelope? result = null;
            plaintext.UseMaterial(material =>
            {
                byte[] nonce = RandomNumberGenerator.GetBytes(12);
                byte[] ciphertext = new byte[material.Length];
                byte[] tag = new byte[16];
                using AesGcm aes = new(_root, 16);
                aes.Encrypt(nonce, material, ciphertext, tag, AssociatedData(purpose, authenticatedContext.Span));
                byte[] payload = new byte[nonce.Length + tag.Length + ciphertext.Length];
                nonce.CopyTo(payload, 0);
                tag.CopyTo(payload, 12);
                ciphertext.CopyTo(payload, 28);
                result = new ProtectedStoreEnvelope(CurrentReference, purpose, payload);
                if (purpose == ProtectionPurpose.KeyMaterial)
                {
                    Interlocked.Increment(ref _materials);
                    Interlocked.Exchange(ref _was32, material.Length == 32 ? 1 : 0);
                }
            });
            return ValueTask.FromResult(result!);
        }

        public ValueTask<SensitiveMaterialLease> UnprotectAsync(ProtectedStoreEnvelope envelope,
            ProtectionPurpose expectedPurpose, ReadOnlyMemory<byte> authenticatedContext,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (envelope.Protector != CurrentReference || envelope.Purpose != expectedPurpose)
            {
                throw new CryptographicException("Wrong protector context.");
            }

            byte[] encoded = envelope.ExportEncodedCopy();
            if (encoded.Length < 29)
            {
                throw new CryptographicException("Malformed test envelope.");
            }

            byte[] plaintext = new byte[encoded.Length - 28];
            try
            {
                using AesGcm aes = new(_root, 16);
                aes.Decrypt(encoded.AsSpan(0, 12), encoded.AsSpan(28), encoded.AsSpan(12, 16), plaintext,
                    AssociatedData(expectedPurpose, authenticatedContext.Span));
                return ValueTask.FromResult(SensitiveMaterialLease.TakeOwnership(plaintext));
            }
            catch
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw;
            }
        }

        private byte[] AssociatedData(ProtectionPurpose purpose, ReadOnlySpan<byte> context)
        {
            byte[] prefix = Encoding.ASCII.GetBytes($"{CurrentReference}/{purpose}/");
            byte[] combined = new byte[prefix.Length + context.Length];
            prefix.CopyTo(combined, 0);
            context.CopyTo(combined.AsSpan(prefix.Length));
            return combined;
        }

        public void Dispose() => CryptographicOperations.ZeroMemory(_root);
    }
}
