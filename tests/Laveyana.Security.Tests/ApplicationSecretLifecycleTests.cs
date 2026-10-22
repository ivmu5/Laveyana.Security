using System.Text;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Secrets;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Recovery;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Examples proving fail-closed application flows with existing public APIs.</summary>
[TestFixture]
internal sealed class ApplicationSecretLifecycleTests
{
    [Test]
    public void MissingSecretForExistingDataNeverTriggersCreation()
    {
        ProviderId providerId = ProviderId.New();
        SecretReference reference = new(providerId, SecretId.New());
        MemorySecretProvider provider = new(providerId);

        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await UseRequiredExistingAsync(reference, provider, _ => { }));

        Assert.That(provider.WriteCalls, Is.Zero);
        Assert.That(provider.DeleteCalls, Is.Zero);
    }

    [Test]
    public async Task ConcealedPlatformLossNeverTriggersCreationOrReplacement()
    {
        ProviderId providerId = ProviderId.New();
        SecretReference reference = new(providerId, SecretId.New());
        MemorySecretProvider provider = new(providerId);
        using (SensitiveMaterialLease initial = SensitiveMaterialLease.CreateCopy("existing-key-material"u8))
        {
            await provider.SetAsync(reference, initial);
        }

        provider.HideReads = true; // Simulates a platform backend that reports null after loss.
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await UseRequiredExistingAsync(reference, provider, _ => { }));

        Assert.That(provider.WriteCalls, Is.EqualTo(1));
        Assert.That(provider.DeleteCalls, Is.Zero);
    }

    [Test]
    public async Task ExplicitBackupAndRestoreToNewStoreUsesExistingContracts()
    {
        ProviderId providerId = ProviderId.New();
        SecretReference reference = new(providerId, SecretId.New());
        MemorySecretProvider oldDevice = new(providerId);
        MemorySecretProvider newDevice = new(providerId);
        using SensitiveMaterialLease recoverySecret = PortableKeyRecovery.GenerateRecoverySecret();
        byte[] expected = Encoding.UTF8.GetBytes("exportable-test-key-material");
        byte[] scope = Encoding.UTF8.GetBytes(
            "com.example.application|app-data-key|11111111-1111-4111-8111-111111111111|v1");

        using (SensitiveMaterialLease initial = SensitiveMaterialLease.CreateCopy(expected))
        {
            await oldDevice.SetAsync(reference, initial);
        }

        byte[]? package = null;
        await UseRequiredExistingAsync(reference, oldDevice, value =>
        {
            using SensitiveMaterialLease material = SensitiveMaterialLease.CreateCopy(value);
            package = PortableKeyRecovery.Protect(material, recoverySecret, scope);
        });
        Assert.That(package, Is.Not.Null);

        // The application explicitly chooses restore; no GetOrCreate or silent fallback.
        using (SensitiveMaterialLease recovered =
            PortableKeyRecovery.Unprotect(package!, recoverySecret, scope))
        {
            await newDevice.SetAsync(reference, recovered);
        }

        byte[]? observed = null;
        await UseRequiredExistingAsync(reference, newDevice, value => observed = value.ToArray());
        Assert.That(observed, Is.EqualTo(expected));
        Assert.That(newDevice.WriteCalls, Is.EqualTo(1));
        Assert.That(oldDevice.WriteCalls, Is.EqualTo(1));
    }

    private static async Task UseRequiredExistingAsync(
        SecretReference reference, ISecretProvider provider, SensitiveMaterialAction readMaterial)
    {
        SecretHandle handle = new(reference, provider);
        if (!await handle.UseMaterialAsync(readMaterial).ConfigureAwait(false))
        {
            // For an already existing encrypted dataset, absence is NOT permission to regenerate.
            throw new InvalidOperationException("Existing data key unavailable; explicit recovery is required.");
        }
    }

    private sealed class MemorySecretProvider(ProviderId providerId) : ISecretManagementProvider
    {
        private byte[]? _secret;

        public ProviderId ProviderId { get; } = providerId;

        public bool HideReads { get; set; }

        public int WriteCalls { get; private set; }

        public int DeleteCalls { get; private set; }

        public ValueTask<SecretDescriptor?> FindAsync(
            SecretReference reference, CancellationToken cancellationToken = default)
        {
            EnsureReference(reference);
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<SecretDescriptor?>(
                !HideReads && _secret is not null
                    ? new SecretDescriptor(reference, canOpenMaterial: true)
                    : null);
        }

        public ValueTask<SecretReadResult?> GetAsync(
            SecretReference reference, CancellationToken cancellationToken = default)
        {
            EnsureReference(reference);
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<SecretReadResult?>(
                HideReads || _secret is null
                    ? null
                    : new SecretReadResult(reference, SensitiveMaterialLease.CreateCopy(_secret)));
        }

        public ValueTask SetAsync(
            SecretReference reference, SensitiveMaterialLease material,
            CancellationToken cancellationToken = default)
        {
            EnsureReference(reference);
            cancellationToken.ThrowIfCancellationRequested();
            material.UseMaterial(bytes => _secret = bytes.ToArray());
            WriteCalls++;
            return ValueTask.CompletedTask;
        }

        public ValueTask DeleteAsync(
            SecretReference reference, CancellationToken cancellationToken = default)
        {
            EnsureReference(reference);
            cancellationToken.ThrowIfCancellationRequested();
            _secret = null;
            DeleteCalls++;
            return ValueTask.CompletedTask;
        }

        private void EnsureReference(SecretReference reference)
        {
            if (!reference.IsDefined || reference.ProviderId != ProviderId)
            {
                throw new ArgumentException("Secret reference does not belong to the provider.",
                    nameof(reference));
            }
        }
    }
}
