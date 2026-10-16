using System.Security.Cryptography;
using System.Text.Json;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Secrets;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Secrets;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Tests read-only secret routing, scoped ownership and optional management.</summary>
[TestFixture]
internal sealed class SecretManagementTests
{
    private static readonly ProviderId First = new(Guid.Parse("11111111-1111-4111-8111-111111111111"));
    private static readonly ProviderId Second = new(Guid.Parse("22222222-2222-4222-8222-222222222222"));
    private static readonly SecretId Secret = new(Guid.Parse("33333333-3333-4333-8333-333333333333"));
    private static readonly SecretId OtherSecret = new(Guid.Parse("44444444-4444-4444-8444-444444444444"));

    private static SecretReference Reference(ProviderId provider) => new(provider, Secret);

    [Test]
    public void BaseContractIsReadOnlyAndDoesNotInheritManagement()
    {
        Assert.Multiple(() =>
        {
            Assert.That(typeof(ISecretProvider).Assembly, Is.EqualTo(typeof(SecretId).Assembly));
            Assert.That(typeof(SecretHandle).Assembly, Is.EqualTo(typeof(SecretId).Assembly));
            Assert.That(typeof(ISecretProvider).GetMethods().Select(method => method.Name),
                Is.EquivalentTo(new[] { "get_ProviderId", "FindAsync", "GetAsync" }));
            Assert.That(typeof(ISecretProvider).IsAssignableTo(typeof(ISecretManagementProvider)), Is.False);
            Assert.That(typeof(ISecretManagementProvider).IsAssignableTo(typeof(ISecretProvider)), Is.True);
        });
    }

    [Test]
    public void RegistryUsesExactProviderWithoutScanningOrAliasFallback()
    {
        FakeProvider a = new(First);
        FakeProvider b = new(Second);
        SecretProviderRegistry registry = new([
            new SecretProviderRegistration(a, new ProviderAlias("Primary")),
            new SecretProviderRegistration(b, new ProviderAlias("Secondary"))
        ]);
        Assert.That(registry.Count, Is.EqualTo(2));
        Assert.That(registry.ResolveAlias(new ProviderAlias("Secondary")), Is.EqualTo(Second));
        Assert.That(registry.TryResolveAlias(new ProviderAlias("secondary"), out _), Is.False);
        Assert.That(registry.CreateHandle(Reference(Second)).Reference, Is.EqualTo(Reference(Second)));
        Assert.Throws<KeyNotFoundException>(() => registry.CreateHandle(Reference(ProviderId.New())));
        Assert.That(a.ReadCount, Is.Zero);
        Assert.That(b.ReadCount, Is.Zero);
        Assert.That(a.FindCount, Is.Zero);
        Assert.That(b.FindCount, Is.Zero);
    }

    [Test]
    public void DuplicateIdentityAliasAndUndefinedConfigurationFail()
    {
        Assert.Throws<ArgumentException>(() => new SecretProviderRegistration(new FakeProvider(default)));
        Assert.Throws<ArgumentException>(() => new SecretProviderRegistration(new FakeProvider(First), default(ProviderAlias)));
        Assert.Throws<ArgumentNullException>(() => new SecretProviderRegistration(null!));
        Assert.Throws<ArgumentException>(() => new SecretProviderRegistry([
            new SecretProviderRegistration(new FakeProvider(First)),
            new SecretProviderRegistration(new FakeProvider(First))
        ]));
        Assert.Throws<ArgumentException>(() => new SecretProviderRegistry([
            new SecretProviderRegistration(new FakeProvider(First), new ProviderAlias("Duplicate")),
            new SecretProviderRegistration(new FakeProvider(Second), new ProviderAlias("Duplicate"))
        ]));
        Assert.Throws<ArgumentException>(() => new SecretProviderRegistry([null!]));
        Assert.Throws<ArgumentException>(() => new SecretProviderRegistry([]).CreateHandle(default));
        Assert.Throws<ArgumentException>(() => new SecretHandle(Reference(First), new FakeProvider(Second)));
    }

    [Test]
    public async Task FindReturnsNullForAbsenceAndValidatesExactIdentity()
    {
        FakeProvider provider = new(First);
        SecretProviderRegistry registry = new([new SecretProviderRegistration(provider)]);
        Assert.That(await registry.FindAsync(Reference(First)), Is.Null);
        provider.Find = _ => new SecretDescriptor(Reference(First), canOpenMaterial: true);
        SecretDescriptor? found = await registry.FindAsync(Reference(First));
        Assert.That(found?.Reference, Is.EqualTo(Reference(First)));
        provider.Find = _ => new SecretDescriptor(new SecretReference(First, OtherSecret));
        Assert.ThrowsAsync<InvalidOperationException>(async () => await registry.FindAsync(Reference(First)));
        provider.Find = _ => new SecretDescriptor(Reference(First));
        provider.ProviderId = Second;
        Assert.ThrowsAsync<InvalidOperationException>(async () => await registry.FindAsync(Reference(First)));
    }

    [Test]
    public async Task MissingSecretDoesNotInvokeCallback()
    {
        FakeProvider provider = new(First);
        SecretProviderRegistry registry = new([new SecretProviderRegistration(provider)]);
        bool invoked = false;
        bool found = await registry.UseMaterialAsync(Reference(First), _ => invoked = true);
        Assert.That(found, Is.False);
        Assert.That(invoked, Is.False);
        Assert.That(provider.ReadCount, Is.EqualTo(1));
    }

    [Test]
    public async Task ScopedReadWipesExactOwnedBytesOnSuccess()
    {
        byte[] material = [1, 2, 3, 4, 5];
        FakeProvider provider = new(First)
        {
            Read = reference => new SecretReadResult(reference, SensitiveMaterialLease.TakeOwnership(material))
        };
        SecretProviderRegistry registry = new([new SecretProviderRegistration(provider)]);
        byte[]? observedCopy = null;
        bool found = await registry.UseMaterialAsync(Reference(First), bytes => observedCopy = bytes.ToArray());
        Assert.That(found, Is.True);
        Assert.That(observedCopy, Is.EqualTo(new byte[] { 1, 2, 3, 4, 5 }));
        Assert.That(material, Is.All.EqualTo((byte)0));
        CryptographicOperations.ZeroMemory(observedCopy!);
    }

    [Test]
    public void CallbackFailureWipesMaterialAndPropagates()
    {
        byte[] owned = [5, 4, 3, 2, 1];
        FakeProvider provider = new(First)
        {
            Read = reference => new SecretReadResult(reference, SensitiveMaterialLease.TakeOwnership(owned))
        };
        SecretHandle handle = new(Reference(First), provider);
        Assert.ThrowsAsync<InvalidOperationException>(async () => await handle.UseMaterialAsync(_ =>
            throw new InvalidOperationException("Callback failure.")));
        Assert.That(owned, Is.All.EqualTo((byte)0));
    }

    [Test]
    public void ProviderCannotSubstituteSecretOrProviderIdentity()
    {
        byte[] owned = [7, 7, 7];
        FakeProvider provider = new(First)
        {
            Read = _ => new SecretReadResult(
                new SecretReference(First, OtherSecret),
                SensitiveMaterialLease.TakeOwnership(owned))
        };
        SecretHandle handle = new(Reference(First), provider);
        bool visited = false;
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await handle.UseMaterialAsync(_ => visited = true));
        Assert.That(visited, Is.False);
        Assert.That(owned, Is.All.EqualTo((byte)0));
    }

    [Test]
    public void CancellationAfterProviderReadStillWipesMaterial()
    {
        using CancellationTokenSource source = new();
        byte[] owned = [8, 8, 8];
        FakeProvider provider = new(First)
        {
            Read = reference =>
            {
                source.Cancel();
                return new SecretReadResult(reference, SensitiveMaterialLease.TakeOwnership(owned));
            }
        };
        bool invoked = false;
        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await new SecretHandle(Reference(First), provider).UseMaterialAsync(_ => invoked = true, source.Token));
        Assert.That(invoked, Is.False);
        Assert.That(owned, Is.All.EqualTo((byte)0));
    }

    [Test]
    public void ChangedProviderIdentityAfterGetWipesBeforeRejecting()
    {
        byte[] owned = [3, 3, 3];
        FakeProvider provider = new(First);
        provider.Read = reference =>
        {
            SecretReadResult result = new(reference, SensitiveMaterialLease.TakeOwnership(owned));
            provider.ProviderId = Second;
            return result;
        };
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await new SecretHandle(Reference(First), provider).UseMaterialAsync(_ => { }));
        Assert.That(owned, Is.All.EqualTo((byte)0));
    }

    [Test]
    public void ReadResultCannotBeSerializedOrUsedAfterDisposal()
    {
        byte[] owned = [1, 5, 9];
        SecretReadResult result = new(Reference(First), SensitiveMaterialLease.TakeOwnership(owned));
        Assert.That(result.ToString(), Does.Not.Contain("159"));
        Assert.Throws<NotSupportedException>(() => JsonSerializer.Serialize(result));
        Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<SecretReadResult>("{}"));
        result.Dispose();
        result.Dispose();
        Assert.That(owned, Is.All.EqualTo((byte)0));
        Assert.Throws<ObjectDisposedException>(() => result.UseMaterial(_ => { }));
    }

    [Test]
    public void DescriptorCapabilitiesAreIndependentAndFailClosedByDefault()
    {
        SecretDescriptor plain = new(Reference(First));
        SecretDescriptor open = new(Reference(First), canOpenMaterial: true);
        SecretDescriptor export = new(Reference(First), canOpenMaterial: true, canExportMaterial: true);
        Assert.That(plain.CanOpenMaterial, Is.False);
        Assert.That(plain.CanExportMaterial, Is.False);
        Assert.That(open.CanOpenMaterial, Is.True);
        Assert.That(open.CanExportMaterial, Is.False);
        Assert.That(export.CanExportMaterial, Is.True);
        Assert.Throws<ArgumentException>(() => new SecretDescriptor(Reference(First), canExportMaterial: true));
    }

    [Test]
    public void ManagementIsOptionalAndNeverUsedForNormalRead()
    {
        FakeProvider readOnly = new(First);
        FakeManagedProvider managed = new(Second);
        SecretProviderRegistry registry = new([
            new SecretProviderRegistration(readOnly),
            new SecretProviderRegistration(managed)
        ]);
        Assert.That(registry.RouteManagement(Reference(Second)), Is.SameAs(managed));
        Assert.Throws<NotSupportedException>(() => registry.RouteManagement(Reference(First)));
        Assert.That(readOnly.ReadCount, Is.Zero);
        Assert.That(managed.ReadCount, Is.Zero);
    }

    private class FakeProvider(ProviderId providerId) : ISecretProvider
    {
        public ProviderId ProviderId { get; set; } = providerId;
        public Func<SecretReference, SecretDescriptor?> Find { get; set; } = _ => null;
        public Func<SecretReference, SecretReadResult?> Read { get; set; } = _ => null;
        public int FindCount { get; private set; }
        public int ReadCount { get; private set; }

        public ValueTask<SecretDescriptor?> FindAsync(SecretReference reference, CancellationToken cancellationToken = default)
        {
            FindCount++;
            return ValueTask.FromResult(Find(reference));
        }

        public ValueTask<SecretReadResult?> GetAsync(SecretReference reference, CancellationToken cancellationToken = default)
        {
            ReadCount++;
            return ValueTask.FromResult(Read(reference));
        }
    }

    private sealed class FakeManagedProvider(ProviderId providerId) : FakeProvider(providerId), ISecretManagementProvider
    {
        public ValueTask SetAsync(SecretReference reference, SensitiveMaterialLease material, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        public ValueTask DeleteAsync(SecretReference reference, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;
    }
}
