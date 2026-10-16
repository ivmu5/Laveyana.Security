using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Providers;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Exercises provider contracts and identity-safe routing with external-style fakes.</summary>
[TestFixture]
internal sealed class ProviderRegistryTests
{
    private static readonly ProviderId First = new(Guid.Parse("11111111-1111-4111-8111-111111111111"));
    private static readonly ProviderId Second = new(Guid.Parse("22222222-2222-4222-8222-222222222222"));
    private static readonly KeyId Key = new(Guid.Parse("33333333-3333-4333-8333-333333333333"));
    private static readonly KeyId OtherKey = new(Guid.Parse("44444444-4444-4444-8444-444444444444"));
    private static readonly AlgorithmId Algorithm = new("aes-256-gcm");

    [Test]
    public void EmptyRegistryIsValidButNeverScansForUnknownKeys()
    {
        ProviderRegistry registry = new([]);
        Assert.That(registry.Count, Is.Zero);
        Assert.That(registry.TryResolveAlias(new ProviderAlias("Missing"), out _), Is.False);
        Assert.Throws<KeyNotFoundException>(() => registry.GetRequired(First));
        Assert.Throws<KeyNotFoundException>(() => registry.Route(Logical(First)));
        Assert.Throws<KeyNotFoundException>(() => registry.ResolveAlias(new ProviderAlias("Missing")));
    }

    [Test]
    public void RegistryRoutesAllFormsOnlyByPersistentProviderId()
    {
        FakeBackend first = new(First);
        FakeBackend second = new(Second);
        ProviderRegistry registry = new([
            new ProviderRegistration(first, new ProviderAlias("Primary")),
            new ProviderRegistration(second, new ProviderAlias("Backup"))
        ]);
        LogicalKeyHandle logical = Logical(Second);
        ExactKeyHandle exact = logical.AtVersion(new KeyVersion(3));

        Assert.Multiple(() =>
        {
            Assert.That(registry.Count, Is.EqualTo(2));
            Assert.That(registry.GetRequired(Second), Is.SameAs(second));
            Assert.That(registry.Route(logical), Is.SameAs(second));
            Assert.That(registry.Route(exact), Is.SameAs(second));
            Assert.That(registry.Route(exact.Reference), Is.SameAs(second));
            Assert.That(registry.ResolveAlias(new ProviderAlias("Backup")), Is.EqualTo(Second));
            Assert.That(first.LogicalReads, Is.Zero);
            Assert.That(second.LogicalReads, Is.Zero);
        });
    }

    [Test]
    public void DuplicateProviderIdsOrAliasesFailAtConstruction()
    {
        FakeBackend a = new(First);
        FakeBackend b = new(Second);
        Assert.Throws<ArgumentException>(() => new ProviderRegistry([
            new ProviderRegistration(a, new ProviderAlias("First")),
            new ProviderRegistration(new FakeBackend(First), new ProviderAlias("Second"))
        ]));
        Assert.Throws<ArgumentException>(() => new ProviderRegistry([
            new ProviderRegistration(a, new ProviderAlias("Same")),
            new ProviderRegistration(b, new ProviderAlias("Same"))
        ]));
    }

    [Test]
    public void UnknownProviderDoesNotProbeAnyRegisteredBackend()
    {
        FakeBackend backend = new(First);
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        Assert.ThrowsAsync<KeyNotFoundException>(async () => await registry.FindLogicalAsync(Logical(Second)));
        Assert.ThrowsAsync<KeyNotFoundException>(async () => await registry.FindExactAsync(
            Logical(Second).AtVersion(new KeyVersion(1))));
        Assert.ThrowsAsync<KeyNotFoundException>(async () => await registry.GetCapabilitiesAsync(Second));
        Assert.That(backend.LogicalReads, Is.Zero);
        Assert.That(backend.ExactReads, Is.Zero);
        Assert.That(backend.CapabilityReads, Is.Zero);
    }

    [Test]
    public void ExternalContractLivesInTheAbstractionsAssembly()
    {
        Assert.Multiple(() =>
        {
            Assert.That(typeof(IKeyProviderBackend).Assembly, Is.EqualTo(typeof(ProviderId).Assembly));
            Assert.That(typeof(IKeyProviderBackend).GetInterfaces(), Does.Contain(typeof(IKeyMetadataResolver)));
            Assert.That(typeof(ProviderCapabilitySnapshot).Assembly, Is.EqualTo(typeof(ProviderId).Assembly));
        });
    }

    [Test]
    public void RuntimeAliasIsCaseSensitiveAndNeverRedirectsAnExistingReference()
    {
        FakeBackend a = new(First);
        FakeBackend b = new(Second);
        ProviderAlias alias = new("Backend");
        ProviderRegistry original = new([new ProviderRegistration(a, alias)]);
        ProviderRegistry replacement = new([new ProviderRegistration(b, alias), new ProviderRegistration(a)]);
        KeyReference reference = Logical(First).AtVersion(new KeyVersion(1)).Reference;

        Assert.Multiple(() =>
        {
            Assert.That(original.TryResolveAlias(new ProviderAlias("backend"), out _), Is.False);
            Assert.That(original.ResolveAlias(alias), Is.EqualTo(First));
            Assert.That(replacement.ResolveAlias(alias), Is.EqualTo(Second));
            Assert.That(original.Route(reference), Is.SameAs(a));
            Assert.That(replacement.Route(reference), Is.SameAs(a));
        });
    }

    [Test]
    public void ConfigurationEnumerationIsMaterializedOnce()
    {
        List<ProviderRegistration> entries = [new(new FakeBackend(First), new ProviderAlias("One"))];
        ProviderRegistry registry = new(entries);
        entries.Clear();
        Assert.That(registry.Count, Is.EqualTo(1));
        Assert.That(registry.ResolveAlias(new ProviderAlias("One")), Is.EqualTo(First));
    }

    [Test]
    public void UndefinedIdentityAndMissingBackendsAreRejected()
    {
        ProviderRegistry registry = new([]);
        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentException>(() => new ProviderRegistration(new FakeBackend(default)));
            Assert.Throws<ArgumentException>(() => new ProviderRegistration(new FakeBackend(First), default(ProviderAlias)));
            Assert.Throws<ArgumentNullException>(() => new ProviderRegistration(null!));
            Assert.Throws<ArgumentException>(() => registry.GetRequired(default));
            Assert.Throws<ArgumentException>(() => registry.Route(default(LogicalKeyHandle)));
            Assert.Throws<ArgumentException>(() => registry.Route(default(ExactKeyHandle)));
            Assert.Throws<ArgumentException>(() => registry.Route(default(KeyReference)));
            Assert.Throws<ArgumentException>(() => registry.TryResolveAlias(default, out _));
        });
    }

    [Test]
    public void BackendIdentityChangesFailClosed()
    {
        FakeBackend backend = new(First);
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        backend.ProviderId = Second;
        Assert.Throws<InvalidOperationException>(() => registry.GetRequired(First));
    }

    [Test]
    public async Task LogicalAndExactReadsDoNotScanOtherProviders()
    {
        FakeBackend a = new(First);
        FakeBackend b = new(Second);
        ProviderRegistry registry = new([new ProviderRegistration(a), new ProviderRegistration(b)]);
        LogicalKeyHandle logical = Logical(Second);
        ExactKeyHandle exact = logical.AtVersion(new KeyVersion(3));
        KeyDescriptor? result = await registry.FindLogicalAsync(logical);
        KeyVersionDescriptor? version = await registry.FindExactAsync(exact);

        Assert.Multiple(() =>
        {
            Assert.That(result!.ProviderId, Is.EqualTo(Second));
            Assert.That(version!.Reference, Is.EqualTo(exact.Reference));
            Assert.That(a.LogicalReads, Is.Zero);
            Assert.That(a.ExactReads, Is.Zero);
            Assert.That(b.LogicalReads, Is.EqualTo(1));
            Assert.That(b.ExactReads, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task AbsenceIsReturnedOnlyFromTheExactProvider()
    {
        FakeBackend backend = new(First) { ReturnAbsent = true };
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        Assert.That(await registry.FindLogicalAsync(Logical(First)), Is.Null);
        Assert.That(await registry.FindExactAsync(Logical(First).AtVersion(new KeyVersion(1))), Is.Null);
    }

    [Test]
    public void WrongIdentityMetadataIsRejectedWithoutFallback()
    {
        FakeBackend backend = new(First) { ReturnWrongKey = true };
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        Assert.ThrowsAsync<InvalidOperationException>(async () => await registry.FindLogicalAsync(Logical(First)));
        Assert.ThrowsAsync<InvalidOperationException>(async () => await registry.FindExactAsync(Logical(First).AtVersion(new KeyVersion(1))));
        Assert.That(backend.LogicalReads, Is.EqualTo(1));
        Assert.That(backend.ExactReads, Is.EqualTo(1));
    }

    [Test]
    public async Task SnapshotCopiesAndSortsCapabilitiesWithoutGrantingPermission()
    {
        CapabilityId[] source = [WellKnownCapabilities.VerifyMac, WellKnownCapabilities.Encrypt];
        ProviderCapabilitySnapshot snapshot = new(First, source);
        source[0] = WellKnownCapabilities.ExportMaterial;

        Assert.Multiple(() =>
        {
            Assert.That(snapshot.Capabilities, Is.EqualTo(new[] { WellKnownCapabilities.Encrypt, WellKnownCapabilities.VerifyMac }));
            Assert.That(snapshot.Supports(WellKnownCapabilities.Encrypt), Is.True);
            Assert.That(snapshot.Supports(WellKnownCapabilities.ExportMaterial), Is.False);
            Assert.That(snapshot.Capabilities, Is.Not.InstanceOf<CapabilityId[]>());
            Assert.That(snapshot.ToString(), Is.EqualTo("ProviderCapabilitySnapshot"));
        });

        FakeBackend backend = new(First) { Capabilities = snapshot };
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        ProviderCapabilitySnapshot received = await registry.GetCapabilitiesAsync(First);
        Assert.That(received.Supports(WellKnownCapabilities.Encrypt), Is.True);
        Assert.That(received.Supports(WellKnownCapabilities.Sign), Is.False);
        Assert.That(backend.CapabilityReads, Is.EqualTo(1));
    }

    [Test]
    public void InvalidCapabilityDeclarationsAreRejected()
    {
        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentException>(() => new ProviderCapabilitySnapshot(default, []));
            Assert.Throws<ArgumentNullException>(() => new ProviderCapabilitySnapshot(First, null!));
            Assert.Throws<ArgumentException>(() => new ProviderCapabilitySnapshot(First, [default(CapabilityId)]));
            Assert.Throws<ArgumentException>(() => new ProviderCapabilitySnapshot(First,
                [WellKnownCapabilities.Encrypt, WellKnownCapabilities.Encrypt]));
            Assert.Throws<ArgumentException>(() => new ProviderCapabilitySnapshot(First,
                Enumerable.Repeat(WellKnownCapabilities.Encrypt, 65)));
            Assert.Throws<ArgumentException>(() => new ProviderCapabilitySnapshot(First, []).Supports(default));
        });
    }

    [Test]
    public void IncorrectProviderCapabilityIdentityIsRejected()
    {
        FakeBackend backend = new(First)
        {
            Capabilities = new ProviderCapabilitySnapshot(Second, [WellKnownCapabilities.Encrypt])
        };
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        Assert.ThrowsAsync<InvalidOperationException>(async () => await registry.GetCapabilitiesAsync(First));
    }

    [Test]
    public void CancellationDoesNotDispatchAnyBackendReads()
    {
        FakeBackend backend = new(First);
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        using CancellationTokenSource source = new();
        source.Cancel();

        Assert.ThrowsAsync<OperationCanceledException>(async () => await registry.FindLogicalAsync(Logical(First), source.Token));
        Assert.ThrowsAsync<OperationCanceledException>(async () => await registry.FindExactAsync(
            Logical(First).AtVersion(new KeyVersion(1)), source.Token));
        Assert.ThrowsAsync<OperationCanceledException>(async () => await registry.GetCapabilitiesAsync(First, source.Token));
        Assert.Multiple(() =>
        {
            Assert.That(backend.LogicalReads, Is.Zero);
            Assert.That(backend.ExactReads, Is.Zero);
            Assert.That(backend.CapabilityReads, Is.Zero);
        });
    }

    [Test]
    public void RegistryBoundsProviderCountAndRejectsNullEntries()
    {
        Assert.Throws<ArgumentException>(() => new ProviderRegistry([null!]));
        IEnumerable<ProviderRegistration> many = Enumerable.Range(0, 1025).Select(i =>
            new ProviderRegistration(new FakeBackend(new ProviderId(GuidFromIndex(i)))));
        Assert.Throws<ArgumentException>(() => new ProviderRegistry(many));
    }

    [Test]
    public void BackendSwitchingIdentityDuringReadsIsRejected()
    {
        FakeBackend backend = new(First) { ChangeIdentityAfterRead = true };
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        Assert.ThrowsAsync<InvalidOperationException>(async () => await registry.FindLogicalAsync(Logical(First)));
    }

    [Test]
    public void MetadataReadCancellationPropagatesFromBackend()
    {
        FakeBackend backend = new(First) { CancelRead = true };
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        Assert.ThrowsAsync<OperationCanceledException>(async () => await registry.FindLogicalAsync(Logical(First)));
    }

    private static Guid GuidFromIndex(int index)
    {
        byte[] bytes = new byte[16];
        BitConverter.TryWriteBytes(bytes, index + 1);
        return new Guid(bytes);
    }

    [Test]
    public async Task ProviderRegistryCanServeAsMetadataResolverForTypedKeyViews()
    {
        FakeBackend backend = new(First);
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        EncryptionKey key = new(Logical(First), registry);
        KeyCapabilityResolution resolved = await key.ResolveForEncryptAsync();
        Assert.That(resolved.ExactHandle.Reference.ProviderId, Is.EqualTo(First));
        Assert.That(resolved.Capability, Is.EqualTo(WellKnownCapabilities.Encrypt));
        Assert.That((await registry.GetCapabilitiesAsync(First)).Supports(WellKnownCapabilities.Encrypt), Is.False,
            "Key-level declarations do not imply provider-wide support.");
    }

    private static LogicalKeyHandle Logical(ProviderId provider) => new(provider, Key);

    /// <summary>A fake provider compiled against Abstractions, with no storage contracts.</summary>
    private sealed class FakeBackend : IKeyProviderBackend
    {
        internal FakeBackend(ProviderId providerId)
        {
            ProviderId = providerId;
        }

        public ProviderId ProviderId { get; set; }
        internal int LogicalReads { get; private set; }
        internal int ExactReads { get; private set; }
        internal int CapabilityReads { get; private set; }
        internal bool ReturnAbsent { get; set; }
        internal bool ReturnWrongKey { get; set; }
        internal bool ChangeIdentityAfterRead { get; set; }
        internal bool CancelRead { get; set; }
        internal ProviderCapabilitySnapshot? Capabilities { get; set; }

        public ValueTask<ProviderCapabilitySnapshot> GetCapabilitiesAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CapabilityReads++;
            return ValueTask.FromResult(Capabilities ?? new ProviderCapabilitySnapshot(ProviderId, []));
        }

        public ValueTask<KeyDescriptor?> FindLogicalAsync(
            LogicalKeyHandle handle,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LogicalReads++;
            if (CancelRead)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            if (ChangeIdentityAfterRead)
            {
                ProviderId = Second;
            }

            if (ReturnAbsent)
            {
                return ValueTask.FromResult<KeyDescriptor?>(null);
            }

            return ValueTask.FromResult<KeyDescriptor?>(new KeyDescriptor(
                ProviderId, ReturnWrongKey ? OtherKey : handle.KeyId,
                null, KeyKind.Symmetric, LogicalKeyState.Active, new KeyVersion(1)));
        }

        public ValueTask<KeyVersionDescriptor?> FindExactAsync(
            ExactKeyHandle handle,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ExactReads++;
            if (ReturnAbsent)
            {
                return ValueTask.FromResult<KeyVersionDescriptor?>(null);
            }

            KeyReference reference = new(ProviderId, ReturnWrongKey ? OtherKey : handle.Reference.KeyId,
                handle.Reference.Version);
            return ValueTask.FromResult<KeyVersionDescriptor?>(new KeyVersionDescriptor(
                reference, KeyVersionState.Active, Algorithm, [WellKnownCapabilities.Encrypt]));
        }
    }
}
