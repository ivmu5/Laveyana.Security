using System.Reflection;
using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Payloads;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Software;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Unknown stored history cannot acquire a new randomized lifetime through a new backend.</summary>
[TestFixture]
internal sealed class SoftwareNonceLifetimeTests
{
    [Test]
    public async Task RejectedCreationsDoNotAccumulateFreshAesNonceBudgets()
    {
        ProviderId provider = ProviderId.New();
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderBackend backend = new(provider, store, protector);
        CapabilityId[] capabilities = [WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt];
        await backend.CreateAsync(new("taken-name"), WellKnownAlgorithms.Aes256Gcm, capabilities);
        Assert.That(FreshNonceBudgetCount(backend), Is.EqualTo(1));

        for (int i = 0; i < 25; i++)
        {
            Assert.ThrowsAsync<SoftwareKeyConflictException>(async () =>
                await backend.CreateAsync(new("taken-name"), WellKnownAlgorithms.Aes256Gcm, capabilities));
        }

        Assert.That(FreshNonceBudgetCount(backend), Is.EqualTo(1),
            "Uncommitted, rejected AES candidates must not retain live nonce budgets.");
    }

    [Test]
    public async Task CreatingNonAesKeysDoesNotAllocateAesNonceBudgets()
    {
        ProviderId provider = ProviderId.New();
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderBackend backend = new(provider, store, protector);
        await backend.CreateAsync(new("hmac-only"), WellKnownAlgorithms.HmacSha256,
            [WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac]);
        Assert.That(FreshNonceBudgetCount(backend), Is.Zero);
    }

    private static int FreshNonceBudgetCount(SoftwareKeyProviderBackend backend)
    {
        FieldInfo field = typeof(SoftwareKeyProviderBackend).GetField("_freshNonceLifetimes",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        object dictionary = field.GetValue(backend)!;
        return (int)dictionary.GetType().GetProperty("Count")!.GetValue(dictionary)!;
    }

    [Test]
    public async Task AuthenticatedDifferentMaterialCannotInheritAFreshIdentityBudget()
    {
        ProviderId provider = ProviderId.New();
        MaterialOverrideStore store = new(new StorageContractsTests.MemoryStore());
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderBackend backend = new(provider, store, protector);
        KeyDescriptor key = await backend.CreateAsync(new("material-binding"), WellKnownAlgorithms.Aes256Gcm,
            [WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt]);
        LogicalKeyHandle handle = new(provider, key.KeyId);
        KeyReference reference = new(provider, key.KeyId, new(1));
        using SensitiveMaterialLease replacement = SensitiveMaterialLease.TakeOwnership(RandomNumberGenerator.GetBytes(32));
        store.Replacement = await protector.ProtectAsync(replacement, ProtectionPurpose.KeyMaterial,
            KeyStoreProtectionContext.ForKeyMaterial(reference));
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.EncryptAsync(handle, new byte[] { 4 }));
        store.Replacement = null;
        EncryptedPayload payload = await backend.EncryptAsync(handle, new byte[] { 4 });
        Assert.That(await backend.DecryptAsync(payload), Is.EqualTo(new byte[] { 4 }));
    }

    [Test]
    public async Task ReopenedBackendRejectsForwardEncryptionButCanDecryptAndExplicitlyRotate()
    {
        ProviderId provider = ProviderId.New();
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderBackend original = new(provider, store, protector);
        KeyDescriptor key = await original.CreateAsync(new("lifetime"), WellKnownAlgorithms.Aes256Gcm,
            [WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt]);
        LogicalKeyHandle handle = new(provider, key.KeyId);
        byte[] message = [1, 2, 3];
        EncryptedPayload before = await original.EncryptAsync(handle, message);

        SoftwareKeyProviderBackend reopened = new(provider, store, protector);
        CryptographicException? error = Assert.ThrowsAsync<CryptographicException>(async () =>
            await reopened.EncryptAsync(handle, message));
        Assert.That(error!.Message, Does.Contain("nonce history"));
        Assert.That(await reopened.DecryptAsync(before), Is.EqualTo(message));
        Assert.That((await reopened.FindLogicalAsync(handle))!.ActiveVersion, Is.EqualTo(new KeyVersion(1)));

        await reopened.RotateAsync(handle);
        EncryptedPayload after = await reopened.EncryptAsync(handle, message);
        Assert.That(after.Reference.Version, Is.EqualTo(new KeyVersion(2)));
        Assert.That(await reopened.DecryptAsync(before), Is.EqualTo(message));
        Assert.That(await original.DecryptAsync(after), Is.EqualTo(message));
        Assert.ThrowsAsync<CryptographicException>(async () => await original.EncryptAsync(handle, message));
    }

    [Test]
    public async Task GetOrCreateCannotResetAnExistingKeysNonceLifetime()
    {
        ProviderId provider = ProviderId.New();
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderBackend original = new(provider, store, protector);
        CapabilityId[] capabilities = [WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt];
        KeyDescriptor created = await original.CreateAsync(new("existing"), WellKnownAlgorithms.Aes256Gcm, capabilities);
        SoftwareKeyProviderBackend reopened = new(provider, store, protector);
        KeyDescriptor found = await reopened.GetOrCreateAsync(new("existing"), WellKnownAlgorithms.Aes256Gcm, capabilities);
        Assert.That(found.KeyId, Is.EqualTo(created.KeyId));
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await reopened.EncryptAsync(new(provider, found.KeyId), new byte[] { 9 }));
        Assert.That(await original.EncryptAsync(new(provider, created.KeyId), new byte[] { 9 }), Is.Not.Null);
    }

    private sealed class MaterialOverrideStore(IKeyStore inner) : IKeyStore
    {
        internal ProtectedStoreEnvelope? Replacement { get; set; }
        public KeyStoreCapabilities Capabilities => inner.Capabilities;
        public ValueTask<KeyStoreEntry?> FindByNameAsync(ProviderId p, KeyName n, CancellationToken c = default) => inner.FindByNameAsync(p, n, c);
        public ValueTask<KeyStoreEntry?> FindByIdAsync(ProviderId p, KeyId k, CancellationToken c = default) => inner.FindByIdAsync(p, k, c);
        public ValueTask<KeyStoreMaterialReadResult> ReadMaterialAsync(KeyReference r, KeyStoreRevision v, CancellationToken c = default) =>
            Replacement is not null ? ValueTask.FromResult(KeyStoreMaterialReadResult.Found(Replacement)) : inner.ReadMaterialAsync(r, v, c);
        public ValueTask<KeyStoreMutationResult> TryCreateAsync(KeyStoreCreateRequest r, CancellationToken c = default) => inner.TryCreateAsync(r, c);
        public ValueTask<KeyStoreMutationResult> TryReplaceAsync(KeyStoreReplaceRequest r, CancellationToken c = default) => inner.TryReplaceAsync(r, c);
        public ValueTask<KeyStoreMutationResult> TryDeleteAsync(ProviderId p, KeyId k, KeyStoreRevision v, CancellationToken c = default) => inner.TryDeleteAsync(p, k, v, c);
    }
}
