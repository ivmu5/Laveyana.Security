using System.Security.Cryptography;
using System.Text;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Nonce;
using Laveyana.Security.Providers;
using Laveyana.Security.Abstractions.Payloads;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Software;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Phase 16 end-to-end managed AEAD with authenticated stored material and nonce policies.</summary>
[TestFixture]
internal sealed class SoftwareAeadEncryptionTests
{
    private static readonly ProviderId Provider = ProviderId.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly ProviderId OtherProvider = ProviderId.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly KeyName Name = new("AeadMaster");
    private static readonly CapabilityId[] Both = [WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt];
    private static readonly byte[] Aad = "tenant-v1"u8.ToArray();

    private static async Task<(SoftwareKeyProviderBackend Backend, LogicalKeyHandle Handle)> CreateAsync(
        IKeyStore store, IKeyStoreProtector protector, CapabilityId[]? capabilities = null)
    {
        SoftwareKeyProviderBackend backend = new(Provider, store, protector);
        KeyDescriptor descriptor = await backend.CreateAsync(Name, WellKnownAlgorithms.Aes256Gcm,
            capabilities ?? Both);
        return (backend, new LogicalKeyHandle(descriptor.ProviderId, descriptor.KeyId));
    }

    [Test]
    public async Task ActiveEncryptionRoundTripsAndPreservesExactVersion()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateAsync(store, protector);
        byte[] message = Encoding.UTF8.GetBytes("confidential message");
        EncryptedPayload payload = await backend.EncryptAsync(handle, message, Aad);
        Assert.That(payload.Reference, Is.EqualTo(handle.AtVersion(new KeyVersion(1)).Reference));
        Assert.That(payload.Algorithm, Is.EqualTo(WellKnownAlgorithms.Aes256Gcm));
        Assert.That(payload.ExportCiphertextCopy(), Is.Not.EqualTo(message));
        Assert.That(await backend.DecryptAsync(payload, Aad), Is.EqualTo(message));
        Assert.That(await backend.TryDecryptAsync(payload, Aad), Is.EqualTo(message));
        Assert.That(ManagedPayloadCodec.DecodeEncrypted(ManagedPayloadCodec.Encode(payload)).ExportCiphertextCopy(),
            Is.EqualTo(payload.ExportCiphertextCopy()));
        Assert.That((await backend.GetCapabilitiesAsync()).Supports(WellKnownCapabilities.Encrypt), Is.True);
        Assert.That((await backend.GetCapabilitiesAsync()).Supports(WellKnownCapabilities.Mac), Is.True);
    }

    [Test]
    public async Task EmptyInputAndDetachedPayloadRoundTrip()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateAsync(store, protector);
        (DetachedEncryptedPayload metadata, byte[] bytes) = await backend.EncryptDetachedAsync(handle,
            ReadOnlyMemory<byte>.Empty, Aad);
        Assert.That(bytes, Is.Empty);
        Assert.That(await backend.DecryptDetachedAsync(metadata, bytes, Aad), Is.Empty);
        Assert.That(await backend.TryDecryptDetachedAsync(metadata, bytes, Aad), Is.Empty);
        Assert.That(await backend.TryDecryptDetachedAsync(metadata, bytes, "bad"u8.ToArray()), Is.Null);
        Assert.ThrowsAsync<ArgumentException>(async () => await backend.DecryptDetachedAsync(metadata, new byte[] { 9 }, Aad));
    }

    [Test]
    public async Task AnyAlteredAuthenticatedFieldFailsTagVerification()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateAsync(store, protector);
        EncryptedPayload payload = await backend.EncryptAsync(handle, "sensitive"u8.ToArray(), Aad);
        byte[] nonce = payload.ExportNonceCopy();
        byte[] tag = payload.ExportAuthenticationTagCopy();
        byte[] ciphertext = payload.ExportCiphertextCopy();
        nonce[0] ^= 1;
        tag[0] ^= 1;
        ciphertext[0] ^= 1;
        EncryptedPayload badNonce = new(payload.Reference, payload.Algorithm, nonce,
            payload.ExportCiphertextCopy(), payload.ExportAuthenticationTagCopy());
        EncryptedPayload badTag = new(payload.Reference, payload.Algorithm, payload.ExportNonceCopy(),
            payload.ExportCiphertextCopy(), tag);
        EncryptedPayload badCipher = new(payload.Reference, payload.Algorithm, payload.ExportNonceCopy(),
            ciphertext, payload.ExportAuthenticationTagCopy());
        Assert.That(await backend.TryDecryptAsync(payload, "incorrect"u8.ToArray()), Is.Null);
        Assert.That(await backend.TryDecryptAsync(badNonce, Aad), Is.Null);
        Assert.That(await backend.TryDecryptAsync(badTag, Aad), Is.Null);
        Assert.That(await backend.TryDecryptAsync(badCipher, Aad), Is.Null);
        Assert.ThrowsAsync<AuthenticationTagMismatchException>(async () =>
            await backend.DecryptAsync(badTag, Aad));
    }

    [Test]
    public async Task RotationUsesLatestForEncryptAndHistoricForDecrypt()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateAsync(store, protector);
        EncryptedPayload before = await backend.EncryptAsync(handle, new byte[] { 1, 2 }, Aad);
        await backend.RotateAsync(handle);
        EncryptedPayload after = await backend.EncryptAsync(handle, new byte[] { 3, 4 }, Aad);
        Assert.That(before.Reference.Version, Is.EqualTo(new KeyVersion(1)));
        Assert.That(after.Reference.Version, Is.EqualTo(new KeyVersion(2)));
        Assert.That(await backend.DecryptAsync(before, Aad), Is.EqualTo(new byte[] { 1, 2 }));
        Assert.That(await backend.DecryptAsync(after, Aad), Is.EqualTo(new byte[] { 3, 4 }));
        await backend.DeleteVersionAsync(handle, new KeyVersion(1), DateTimeOffset.UtcNow);
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.DecryptAsync(before, Aad));
    }

    [Test]
    public async Task RetiredLogicalKeyCannotEncryptButCanDecryptHistory()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateAsync(store, protector);
        EncryptedPayload old = await backend.EncryptAsync(handle, new byte[] { 1 });
        await backend.RetireAsync(handle);
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.EncryptAsync(handle, new byte[] { 2 }));
        Assert.That(await backend.DecryptAsync(old), Is.EqualTo(new byte[] { 1 }));
    }

    [Test]
    public async Task MissingCapabilityIsDeniedAndNotDowngraded()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateAsync(store, protector,
            [WellKnownCapabilities.Decrypt]);
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.EncryptAsync(handle, new byte[] { 1 }));
        // Make an encrypt-only key and ensure its ciphertext cannot be decrypted via missing capability.
        StorageContractsTests.MemoryStore secondStore = new();
        using SoftwareKeyProviderTests.TestProtector secondProtector = new();
        (SoftwareKeyProviderBackend encryptOnly, LogicalKeyHandle secondHandle) = await CreateAsync(
            secondStore, secondProtector, [WellKnownCapabilities.Encrypt]);
        EncryptedPayload payload = await encryptOnly.EncryptAsync(secondHandle, new byte[] { 1, 2 });
        Assert.ThrowsAsync<CryptographicException>(async () => await encryptOnly.DecryptAsync(payload));
        Assert.ThrowsAsync<CryptographicException>(async () => await encryptOnly.TryDecryptAsync(payload));
    }

    [Test]
    public async Task ForeignProviderAndMissingKeyAreNotAuthenticationFailures()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateAsync(store, protector);
        EncryptedPayload payload = await backend.EncryptAsync(handle, new byte[] { 1 }, Aad);
        SoftwareKeyProviderBackend foreign = new(OtherProvider, store, protector);
        Assert.ThrowsAsync<ArgumentException>(async () => await foreign.TryDecryptAsync(payload, Aad));
        await backend.ForceDeleteAsync(handle);
        Assert.ThrowsAsync<SoftwareKeyConflictException>(async () => await backend.TryDecryptAsync(payload, Aad));
    }

    [Test]
    public async Task RevisionMismatchDoesNotBecomeAnAuthenticationFailure()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore memory = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateAsync(memory, protector);
        EncryptedPayload payload = await backend.EncryptAsync(handle, new byte[] { 1, 2 }, Aad);
        SoftwareKeyProviderBackend stale = new(Provider, new StaleMaterialReadStore(memory), protector);
        Assert.ThrowsAsync<SoftwareKeyConflictException>(async () => await stale.EncryptAsync(handle, new byte[] { 3 }));
        Assert.ThrowsAsync<SoftwareKeyConflictException>(async () => await stale.TryDecryptAsync(payload, Aad));
    }

    [Test]
    public async Task IncorrectAadAndOversizedMessagesAreRejectedBeforeNonceAllocation()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateAsync(store, protector);
        Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await backend.EncryptAsync(handle,
            new byte[16 * 1024 * 1024 + 1]));
        Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await backend.EncryptAsync(handle,
            new byte[] { 0 }, new byte[65_537]));
        using CancellationTokenSource canceled = new();
        await canceled.CancelAsync();
        Assert.ThrowsAsync<OperationCanceledException>(async () => await backend.EncryptAsync(handle,
            new byte[] { 1 }, default, canceled.Token));
        EncryptedPayload payload = await backend.EncryptAsync(handle, new byte[] { 1 });
        Assert.That(await backend.DecryptAsync(payload), Is.EqualTo(new byte[] { 1 }));
    }

    [Test]
    public async Task RegistryRoutesAeadByImmutableProviderIdentity()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateAsync(store, protector);
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        EncryptedPayload payload = await registry.RouteAead(handle).EncryptAsync(handle, new byte[] { 5, 6 });
        Assert.That(await registry.RouteAead(payload.Reference).DecryptAsync(payload), Is.EqualTo(new byte[] { 5, 6 }));
        Assert.Throws<KeyNotFoundException>(() => registry.RouteAead(new KeyReference(OtherProvider,
            handle.KeyId, new KeyVersion(1))));
    }

    [Test]
    public async Task ParallelEncryptionDoesNotRepeatRandomNonceWithinGeneration()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateAsync(store, protector);
        Task<EncryptedPayload>[] tasks = Enumerable.Range(0, 64).Select(_ =>
            backend.EncryptAsync(handle, new byte[] { 1, 2, 3 }).AsTask()).ToArray();
        EncryptedPayload[] results = await Task.WhenAll(tasks);
        Assert.That(results.Select(x => Convert.ToHexString(x.ExportNonceCopy())).Distinct().Count(),
            Is.EqualTo(results.Length));
        Assert.That(results.Select(x => x.Reference).Distinct().Count(), Is.EqualTo(1));
    }

    [Test]
    public async Task SuppliedAllocatorWithoutRollbackProtectionFailsWithoutRandomFallback()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend setup, LogicalKeyHandle handle) = await CreateAsync(store, protector);
        RejectAllocator allocator = new();
        SoftwareKeyProviderBackend usingAllocator = new(Provider, store, protector, allocator);
        Assert.ThrowsAsync<CryptographicException>(async () => await usingAllocator.EncryptAsync(handle, new byte[] { 1 }));
        Assert.That(allocator.WasCalled, Is.False);
    }

    [Test]
    public async Task RebindingPayloadToNewActiveVersionCannotDecrypt()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await CreateAsync(store, protector);
        EncryptedPayload old = await backend.EncryptAsync(handle, new byte[] { 1, 2, 3 }, Aad);
        await backend.RotateAsync(handle);
        EncryptedPayload forged = new(new KeyReference(Provider, handle.KeyId, new KeyVersion(2)),
            old.Algorithm, old.ExportNonceCopy(), old.ExportCiphertextCopy(), old.ExportAuthenticationTagCopy());
        Assert.That(await backend.TryDecryptAsync(forged, Aad), Is.Null);
        Assert.That(await backend.DecryptAsync(old, Aad), Is.EqualTo(new byte[] { 1, 2, 3 }));
    }

    [Test]
    public async Task EncryptSnapshotsCallerAadBeforeWaitingForTheStore()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend authoritative, LogicalKeyHandle handle) = await CreateAsync(store, protector);
        PausedLookupStore pausedStore = new(store);
        SoftwareKeyProviderBackend pendingBackend = new(Provider, pausedStore, protector);
        byte[] expectedAad = "original-encrypt-aad"u8.ToArray();
        byte[] callerOwnedAad = (byte[])expectedAad.Clone();
        byte[] plaintext = [9, 8, 7];

        Task<EncryptedPayload> encryption = pendingBackend.EncryptAsync(handle, plaintext, callerOwnedAad).AsTask();
        await pausedStore.WaitUntilEnteredAsync();
        callerOwnedAad[0] ^= 0xff;
        pausedStore.Release();
        EncryptedPayload payload = await encryption;
        Assert.That(await authoritative.DecryptAsync(payload, expectedAad), Is.EqualTo(plaintext));
        Assert.That(await authoritative.TryDecryptAsync(payload, callerOwnedAad), Is.Null);
    }

    [Test]
    public async Task DecryptSnapshotsCallerAadBeforeWaitingForTheStore()
    {
        if (!AesGcm.IsSupported)
        {
            Assert.Ignore("AES-GCM is unavailable on this host.");
        }
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        (SoftwareKeyProviderBackend authoritative, LogicalKeyHandle handle) = await CreateAsync(store, protector);
        byte[] expectedAad = "original-decrypt-aad"u8.ToArray();
        byte[] plaintext = [7, 8, 9];
        EncryptedPayload payload = await authoritative.EncryptAsync(handle, plaintext, expectedAad);
        PausedLookupStore pausedStore = new(store);
        SoftwareKeyProviderBackend pendingBackend = new(Provider, pausedStore, protector);
        byte[] callerOwnedAad = (byte[])expectedAad.Clone();

        Task<byte[]?> decryption = pendingBackend.TryDecryptAsync(payload, callerOwnedAad).AsTask();
        await pausedStore.WaitUntilEnteredAsync();
        callerOwnedAad[0] ^= 0xff;
        pausedStore.Release();
        Assert.That(await decryption, Is.EqualTo(plaintext));
        Assert.That(await authoritative.TryDecryptAsync(payload, callerOwnedAad), Is.Null);
    }

    /// <summary>Suspends only the metadata lookup, forcing an asynchronous ownership boundary.</summary>
    private sealed class PausedLookupStore(IKeyStore inner) : IKeyStore
    {
        private readonly TaskCompletionSource<bool> _entered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> _resume =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public KeyStoreCapabilities Capabilities => inner.Capabilities;

        public Task WaitUntilEnteredAsync() => _entered.Task.WaitAsync(TimeSpan.FromSeconds(10));

        public void Release() => _resume.TrySetResult(true);

        public ValueTask<KeyStoreEntry?> FindByNameAsync(ProviderId p, KeyName n, CancellationToken c = default) =>
            inner.FindByNameAsync(p, n, c);

        public async ValueTask<KeyStoreEntry?> FindByIdAsync(ProviderId p, KeyId k, CancellationToken c = default)
        {
            _entered.TrySetResult(true);
            await _resume.Task.WaitAsync(c).ConfigureAwait(false);
            return await inner.FindByIdAsync(p, k, c).ConfigureAwait(false);
        }

        public ValueTask<KeyStoreMaterialReadResult> ReadMaterialAsync(KeyReference r,
            KeyStoreRevision v, CancellationToken c = default) => inner.ReadMaterialAsync(r, v, c);

        public ValueTask<KeyStoreMutationResult> TryCreateAsync(KeyStoreCreateRequest r,
            CancellationToken c = default) => inner.TryCreateAsync(r, c);

        public ValueTask<KeyStoreMutationResult> TryReplaceAsync(KeyStoreReplaceRequest r,
            CancellationToken c = default) => inner.TryReplaceAsync(r, c);

        public ValueTask<KeyStoreMutationResult> TryDeleteAsync(ProviderId p, KeyId k,
            KeyStoreRevision v, CancellationToken c = default) => inner.TryDeleteAsync(p, k, v, c);
    }

    /// <summary>Never consulted when the store lacks a verified rollback guarantee.</summary>
    private sealed class RejectAllocator : IRollbackProtectedNonceAllocator
    {
        public bool WasCalled { get; private set; }
        public ValueTask<NonceRangeReservation> ReserveAsync(KeyReference reference, uint count,
            CancellationToken cancellationToken = default)
        {
            WasCalled = true;
            throw new InvalidOperationException("Unverified allocator must never be invoked.");
        }
    }

    /// <summary>Injects a definitive concurrent revision change at the material read boundary.</summary>
    private sealed class StaleMaterialReadStore(IKeyStore inner) : IKeyStore
    {
        public KeyStoreCapabilities Capabilities => inner.Capabilities;
        public ValueTask<KeyStoreEntry?> FindByNameAsync(ProviderId p, KeyName n, CancellationToken c = default) =>
            inner.FindByNameAsync(p, n, c);
        public ValueTask<KeyStoreEntry?> FindByIdAsync(ProviderId p, KeyId k, CancellationToken c = default) =>
            inner.FindByIdAsync(p, k, c);
        public ValueTask<KeyStoreMaterialReadResult> ReadMaterialAsync(KeyReference r,
            KeyStoreRevision v, CancellationToken c = default) => ValueTask.FromResult(
            KeyStoreMaterialReadResult.Rejected(KeyStoreMaterialReadStatus.RevisionMismatch));
        public ValueTask<KeyStoreMutationResult> TryCreateAsync(KeyStoreCreateRequest r,
            CancellationToken c = default) => inner.TryCreateAsync(r, c);
        public ValueTask<KeyStoreMutationResult> TryReplaceAsync(KeyStoreReplaceRequest r,
            CancellationToken c = default) => inner.TryReplaceAsync(r, c);
        public ValueTask<KeyStoreMutationResult> TryDeleteAsync(ProviderId p, KeyId k,
            KeyStoreRevision v, CancellationToken c = default) => inner.TryDeleteAsync(p, k, v, c);
    }
}
