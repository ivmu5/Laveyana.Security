using System.Collections.Concurrent;
using System.IO;
using System.Text;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Secrets;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Maui.Storage;
using Laveyana.Security.Maui.Composition;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Maui.Storage;
using NUnit.Framework;

namespace Laveyana.Security.Tests.Maui;

[TestFixture]
public sealed class MauiSecureStorageSecretProviderTests
{
    [Test]
    public async Task SetGetFindAndDeleteRoundTrip()
    {
        ProviderId id = ProviderId.New();
        SecretReference reference = new(id, SecretId.New());
        MemorySecureStorage storage = new();
        MauiSecureStorageSecretProvider provider = new(id, storage);

        Assert.That(await provider.GetAsync(reference), Is.Null);
        Assert.That(await provider.FindAsync(reference), Is.Null);

        using (SensitiveMaterialLease source = SensitiveMaterialLease.CreateCopy("hello"u8))
        {
            await provider.SetAsync(reference, source);
        }

        Assert.That((await provider.FindAsync(reference))?.CanOpenMaterial, Is.True);
        using (SecretReadResult? result = await provider.GetAsync(reference))
        {
            Assert.That(result, Is.Not.Null);
            byte[]? copy = null;
            result!.UseMaterial(bytes => copy = bytes.ToArray());
            Assert.That(copy, Is.EqualTo(Encoding.UTF8.GetBytes("hello")));
        }

        await provider.DeleteAsync(reference);
        Assert.That(await provider.GetAsync(reference), Is.Null);
        Assert.That(storage.RemoveAllCalls, Is.Zero);
    }

    [Test]
    public void RejectsForeignReferencesBeforeAnyStorageAccess()
    {
        ProviderId id = ProviderId.New();
        SecretReference foreign = new(ProviderId.New(), SecretId.New());
        MemorySecureStorage storage = new();
        MauiSecureStorageSecretProvider provider = new(id, storage);
        Assert.ThrowsAsync<ArgumentException>(async () => await provider.GetAsync(foreign));
        Assert.That(storage.ReadCalls, Is.Zero);
    }

    [Test]
    public async Task IdentitySwappingIsRejectedInsteadOfReturningWrongMaterial()
    {
        ProviderId id = ProviderId.New();
        SecretReference first = new(id, SecretId.New());
        SecretReference second = new(id, SecretId.New());
        MemorySecureStorage storage = new();
        MauiSecureStorageSecretProvider provider = new(id, storage);

        using (SensitiveMaterialLease value = SensitiveMaterialLease.CreateCopy("data"u8))
        {
            await provider.SetAsync(first, value);
        }

        string originalKey = storage.Items.Keys.Single();
        string valueAtFirst = storage.Items[originalKey];
        await provider.DeleteAsync(first);
        using (SensitiveMaterialLease value = SensitiveMaterialLease.CreateCopy("other"u8))
        {
            await provider.SetAsync(second, value);
        }

        string secondKey = storage.Items.Keys.Single();
        storage.Items[secondKey] = valueAtFirst;
        Assert.ThrowsAsync<InvalidDataException>(async () => await provider.GetAsync(second));
        Assert.That(storage.RemoveAllCalls, Is.Zero);
    }

    [Test]
    public void OversizedSecretFailsWithoutWriting()
    {
        ProviderId id = ProviderId.New();
        MemorySecureStorage storage = new();
        MauiSecureStorageSecretProvider provider = new(id, storage);
        using SensitiveMaterialLease large = SensitiveMaterialLease.TakeOwnership(
            new byte[MauiSecureStorageSecretProvider.MaximumSecretLength + 1]);
        SecretReference reference = new(id, SecretId.New());

        Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await provider.SetAsync(reference, large));
        Assert.That(storage.Items, Is.Empty);
    }

    [Test]
    public void CancelledWriteHasNoEffect()
    {
        ProviderId id = ProviderId.New();
        MemorySecureStorage storage = new();
        MauiSecureStorageSecretProvider provider = new(id, storage);
        using SensitiveMaterialLease source = SensitiveMaterialLease.CreateCopy("hello"u8);
        using CancellationTokenSource cancel = new();
        cancel.Cancel();
        SecretReference reference = new(id, SecretId.New());

        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await provider.SetAsync(reference, source, cancel.Token));
        Assert.That(storage.Items, Is.Empty);
    }

    [Test]
    public async Task CorruptEncodingIsRejectedWithoutDeletingOtherEntries()
    {
        ProviderId id = ProviderId.New();
        SecretReference reference = new(id, SecretId.New());
        MemorySecureStorage storage = new();
        MauiSecureStorageSecretProvider provider = new(id, storage);
        using (SensitiveMaterialLease data = SensitiveMaterialLease.CreateCopy("valid"u8))
        {
            await provider.SetAsync(reference, data);
        }

        string key = storage.Items.Keys.Single();
        storage.Items[key] = storage.Items[key][..^4] + "!!!!";
        Assert.ThrowsAsync<InvalidDataException>(async () => await provider.GetAsync(reference));
        Assert.That(storage.Items, Has.Count.EqualTo(1));
        Assert.That(storage.RemoveAllCalls, Is.Zero);
    }

    [Test]
    public void ExplicitDiRegistrationUsesTheProvidedPlatformBackend()
    {
        ProviderId id = ProviderId.New();
        MemorySecureStorage storage = new();
        ServiceCollection services = new();
        services.AddLaveyanaMauiSecureStorage(id, storage);
        Assert.Throws<InvalidOperationException>(() => services.AddLaveyanaMauiSecureStorage(id, storage));

        using ServiceProvider container = services.BuildServiceProvider();
        MauiSecureStorageSecretProvider provider =
            container.GetRequiredService<MauiSecureStorageSecretProvider>();
        Assert.That(provider.ProviderId, Is.EqualTo(id));
    }

    [Test]
    public void PlatformFailureIsPropagatedNotConvertedToAbsence()
    {
        ProviderId id = ProviderId.New();
        MemorySecureStorage storage = new() { ThrowOnRead = true };
        MauiSecureStorageSecretProvider provider = new(id, storage);
        Assert.ThrowsAsync<IOException>(async () => await provider.GetAsync(new(id, SecretId.New())));
    }

    private sealed class MemorySecureStorage : ISecureStorage
    {
        public ConcurrentDictionary<string, string> Items { get; } = new(StringComparer.Ordinal);
        public int RemoveAllCalls { get; private set; }
        public int ReadCalls { get; private set; }
        public bool ThrowOnRead { get; init; }

        public Task<string?> GetAsync(string key)
        {
            ReadCalls++;
            if (ThrowOnRead)
            {
                throw new IOException("Simulated platform failure.");
            }

            return Task.FromResult(Items.TryGetValue(key, out string? value) ? value : null);
        }

        public Task SetAsync(string key, string value)
        {
            Items[key] = value;
            return Task.CompletedTask;
        }

        public bool Remove(string key) => Items.TryRemove(key, out _);

        public void RemoveAll()
        {
            RemoveAllCalls++;
            Items.Clear();
        }
    }
}
