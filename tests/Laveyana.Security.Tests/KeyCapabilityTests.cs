using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>
/// Validates logical/exact selection, typed capability rejection, rotation and
/// fail-closed metadata checks without a persistent provider implementation.
/// </summary>
[TestFixture]
internal sealed class KeyCapabilityTests
{
    private static readonly ProviderId Provider = ProviderId.Parse("12345678-1234-4234-8234-123456789abc");
    private static readonly KeyId Key = KeyId.Parse("12345678-1234-4234-8234-123456789abd");
    private static readonly KeyId OtherKey = KeyId.Parse("12345678-1234-4234-8234-123456789abe");

    private static readonly LogicalKeyHandle Logical = new(Provider, Key);
    private static readonly AlgorithmId Aes = WellKnownAlgorithms.Aes256Gcm;

    private static FakeMetadata Active(KeyKind kind, params CapabilityId[] capabilities)
    {
        FakeMetadata metadata = new(Provider, Key, kind);
        metadata.SetActive(1, Aes, capabilities);
        return metadata;
    }

    [Test]
    public void HandlesRequireStableDefinedIdsAndRedactInLogging()
    {
        ExactKeyHandle exact = Logical.AtVersion(new KeyVersion(3));
        Assert.Multiple(() =>
        {
            Assert.That(exact.Reference, Is.EqualTo(new KeyReference(Provider, Key, new KeyVersion(3))));
            Assert.That(exact.Logical, Is.EqualTo(Logical));
            Assert.That(new ExactKeyHandle(exact.Reference), Is.EqualTo(exact));
            Assert.That(exact.ToString(), Is.EqualTo("ExactKeyHandle"));
            Assert.That(Logical.ToString(), Is.EqualTo("LogicalKeyHandle"));
            Assert.That(default(LogicalKeyHandle).IsDefined, Is.False);
            Assert.That(default(ExactKeyHandle).IsDefined, Is.False);
            Assert.Throws<ArgumentException>(() => new LogicalKeyHandle(default, Key));
            Assert.Throws<ArgumentException>(() => new LogicalKeyHandle(Provider, default));
            Assert.Throws<ArgumentException>(() => new ExactKeyHandle(default));
            Assert.Throws<InvalidOperationException>(() => default(LogicalKeyHandle).AtVersion(new KeyVersion(1)));
            Assert.Throws<InvalidOperationException>(() => Logical.AtVersion(default));
            Assert.Throws<InvalidOperationException>(() => _ = default(ExactKeyHandle).Logical);
        });
    }

    [Test]
    public async Task ForwardViewRefreshesActiveReferenceAfterRotation()
    {
        FakeMetadata metadata = Active(KeyKind.Symmetric, WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt);
        EncryptionKey view = new(Logical, metadata);

        KeyCapabilityResolution first = await view.ResolveForEncryptAsync();
        metadata.Rotate(2, Aes, WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt);
        KeyCapabilityResolution second = await view.ResolveForEncryptAsync();

        Assert.Multiple(() =>
        {
            Assert.That(first.ExactHandle.Reference.Version, Is.EqualTo(new KeyVersion(1)));
            Assert.That(second.ExactHandle.Reference.Version, Is.EqualTo(new KeyVersion(2)));
            Assert.That(first.ExactHandle, Is.Not.EqualTo(second.ExactHandle));
            Assert.That(view.Handle, Is.EqualTo(Logical));
            Assert.That(metadata.LogicalQueries, Is.EqualTo(2));
            Assert.That(first.Capability, Is.EqualTo(WellKnownCapabilities.Encrypt));
            Assert.That(first.Algorithm, Is.EqualTo(Aes));
            Assert.That(first.ToString(), Is.EqualTo("KeyCapabilityResolution"));
        });
    }

    [Test]
    public async Task HistoricalOperationNeverSwitchesVersions()
    {
        FakeMetadata metadata = Active(KeyKind.Symmetric, WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt);
        EncryptionKey view = new(Logical, metadata);
        ExactKeyHandle old = Logical.AtVersion(new KeyVersion(1));
        metadata.Rotate(2, Aes, WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt);

        KeyCapabilityResolution historical = await view.ResolveForDecryptAsync(old);
        KeyCapabilityResolution forward = await view.ResolveForEncryptAsync();
        Assert.Multiple(() =>
        {
            Assert.That(historical.ExactHandle, Is.EqualTo(old));
            Assert.That(historical.Capability, Is.EqualTo(WellKnownCapabilities.Decrypt));
            Assert.That(forward.ExactHandle, Is.Not.EqualTo(old));
        });
    }

    [Test]
    public void LogicalAndExactHandlesRejectForeignKeyReferences()
    {
        FakeMetadata metadata = Active(KeyKind.Symmetric, WellKnownCapabilities.Decrypt);
        EncryptionKey view = new(Logical, metadata);
        ExactKeyHandle foreign = new(new KeyReference(Provider, OtherKey, new KeyVersion(1)));

        KeyCapabilityException exception = Assert.ThrowsAsync<KeyCapabilityException>(
            async () => await view.ResolveForDecryptAsync(foreign))!;
        Assert.That(exception.Failure, Is.EqualTo(KeyCapabilityFailure.IdentityMismatch));
    }

    [Test]
    public void CapabilityMustBeDeclaredBySelectedExactVersion()
    {
        FakeMetadata metadata = Active(KeyKind.Symmetric, WellKnownCapabilities.Decrypt);
        EncryptionKey view = new(Logical, metadata);
        KeyCapabilityException exception = Assert.ThrowsAsync<KeyCapabilityException>(
            async () => await view.ResolveForEncryptAsync())!;
        Assert.That(exception.Failure, Is.EqualTo(KeyCapabilityFailure.CapabilityMissing));
    }

    [Test]
    public void WrongKeyKindFailsClosedEvenWhenCapabilityTokenMatches()
    {
        FakeMetadata metadata = Active(KeyKind.AsymmetricPrivate, WellKnownCapabilities.Encrypt);
        EncryptionKey view = new(Logical, metadata);
        KeyCapabilityException exception = Assert.ThrowsAsync<KeyCapabilityException>(
            async () => await view.ResolveForEncryptAsync())!;
        Assert.That(exception.Failure, Is.EqualTo(KeyCapabilityFailure.KindMismatch));
    }

    [Test]
    public void PendingAndDeletedVersionsCannotBeUsed()
    {
        FakeMetadata metadata = Active(KeyKind.Symmetric, WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt);
        EncryptionKey view = new(Logical, metadata);
        metadata.SetVersion(1, KeyVersionState.Pending, Aes, WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt);
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await view.ResolveForEncryptAsync())!.Failure,
            Is.EqualTo(KeyCapabilityFailure.StateRejected));
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await view.ResolveForDecryptAsync(Logical.AtVersion(new KeyVersion(1))))!.Failure,
            Is.EqualTo(KeyCapabilityFailure.StateRejected));

        metadata.SetVersion(1, KeyVersionState.Deleted, Aes, WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt);
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await view.ResolveForDecryptAsync(Logical.AtVersion(new KeyVersion(1))))!.Failure,
            Is.EqualTo(KeyCapabilityFailure.StateRejected));
    }

    [Test]
    public void RetiredLogicalKeysDenyForwardButPermitHistoricalUse()
    {
        FakeMetadata metadata = Active(KeyKind.Symmetric, WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt);
        EncryptionKey view = new(Logical, metadata);
        metadata.Retire();
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await view.ResolveForEncryptAsync())!.Failure,
            Is.EqualTo(KeyCapabilityFailure.StateRejected));
        Assert.DoesNotThrowAsync(async () => await view.ResolveForDecryptAsync(Logical.AtVersion(new KeyVersion(1))));

        metadata.DeleteLogical();
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await view.ResolveForDecryptAsync(Logical.AtVersion(new KeyVersion(1))))!.Failure,
            Is.EqualTo(KeyCapabilityFailure.StateRejected));
    }

    [Test]
    public void MissingLogicalOrExactMetadataFailsClosed()
    {
        FakeMetadata metadata = Active(KeyKind.Symmetric, WellKnownCapabilities.Encrypt, WellKnownCapabilities.Decrypt);
        EncryptionKey view = new(Logical, metadata);
        metadata.LogicalMissing = true;
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await view.ResolveForEncryptAsync())!.Failure,
            Is.EqualTo(KeyCapabilityFailure.NotFound));
        metadata.LogicalMissing = false;
        metadata.ExactMissing = true;
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await view.ResolveForEncryptAsync())!.Failure,
            Is.EqualTo(KeyCapabilityFailure.NotFound));
    }

    [Test]
    public void MismatchedResolverIdentityFailsClosed()
    {
        FakeMetadata metadata = Active(KeyKind.Symmetric, WellKnownCapabilities.Encrypt);
        EncryptionKey view = new(Logical, metadata);
        metadata.ReturnWrongLogical = true;
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await view.ResolveForEncryptAsync())!.Failure,
            Is.EqualTo(KeyCapabilityFailure.IdentityMismatch));
        metadata.ReturnWrongLogical = false;
        metadata.ReturnWrongExact = true;
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await view.ResolveForEncryptAsync())!.Failure,
            Is.EqualTo(KeyCapabilityFailure.IdentityMismatch));
    }

    [Test]
    public void RotationDuringMetadataLookupRejectsStaleSelection()
    {
        FakeMetadata metadata = Active(KeyKind.Symmetric, WellKnownCapabilities.Encrypt);
        EncryptionKey view = new(Logical, metadata);
        metadata.OnLogicalRead = () => metadata.Rotate(2, Aes, WellKnownCapabilities.Encrypt);
        // The logical snapshot records version 1, but rotation retires it before
        // the exact lookup: fail closed rather than silently using old/new material.
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await view.ResolveForEncryptAsync())!.Failure,
            Is.EqualTo(KeyCapabilityFailure.StateRejected));
    }

    [Test]
    public void CancellationPropagatesAndNoMetadataIsRead()
    {
        FakeMetadata metadata = Active(KeyKind.Symmetric, WellKnownCapabilities.Encrypt);
        using CancellationTokenSource canceled = new();
        canceled.Cancel();
        EncryptionKey view = new(Logical, metadata);
        Assert.ThrowsAsync<OperationCanceledException>(async () => await view.ResolveForEncryptAsync(canceled.Token));
        Assert.That(metadata.LogicalQueries, Is.Zero);
    }

    [Test]
    public async Task SymmetricMacAndDerivationRequireIndependentCapabilities()
    {
        FakeMetadata metadata = Active(KeyKind.Symmetric, WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac, WellKnownCapabilities.Derive);
        MacKey mac = new(Logical, metadata);
        DerivationKey derive = new(Logical, metadata);
        Assert.Multiple(() =>
        {
            Assert.That(mac.Handle, Is.EqualTo(Logical));
            Assert.That(derive.Handle, Is.EqualTo(Logical));
            Assert.That(mac.ToString(), Is.EqualTo("MacKey"));
            Assert.That(derive.ToString(), Is.EqualTo("DerivationKey"));
        });
        Assert.That((await mac.ResolveForMacAsync()).Capability, Is.EqualTo(WellKnownCapabilities.Mac));
        Assert.That((await mac.ResolveForVerifyAsync(Logical.AtVersion(new KeyVersion(1)))).Capability,
            Is.EqualTo(WellKnownCapabilities.VerifyMac));
        Assert.That((await derive.ResolveForDeriveAsync()).Capability, Is.EqualTo(WellKnownCapabilities.Derive));

        metadata.SetVersion(1, KeyVersionState.Active, Aes, WellKnownCapabilities.Mac);
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await derive.ResolveForDeriveAsync())!.Failure,
            Is.EqualTo(KeyCapabilityFailure.CapabilityMissing));
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await mac.ResolveForVerifyAsync(Logical.AtVersion(new KeyVersion(1))))!.Failure,
            Is.EqualTo(KeyCapabilityFailure.CapabilityMissing));
    }

    [Test]
    public async Task AsymmetricPrivateAndPublicViewsRejectCrossKindUse()
    {
        FakeMetadata privateMetadata = Active(KeyKind.AsymmetricPrivate, WellKnownCapabilities.Sign, WellKnownCapabilities.KeyAgreement);
        AsymmetricPrivateKey privateKey = new(Logical, privateMetadata);
        Assert.That((await privateKey.ResolveForSignAsync()).Capability, Is.EqualTo(WellKnownCapabilities.Sign));
        Assert.That((await privateKey.ResolveForKeyAgreementAsync()).Capability, Is.EqualTo(WellKnownCapabilities.KeyAgreement));
        Assert.That(privateKey.Handle, Is.EqualTo(Logical));
        Assert.That(privateKey.ToString(), Is.EqualTo("AsymmetricPrivateKey"));
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await new AsymmetricPublicKey(Logical, privateMetadata)
            .ResolveForVerifySignatureAsync(Logical.AtVersion(new KeyVersion(1))))!.Failure,
            Is.EqualTo(KeyCapabilityFailure.KindMismatch));

        FakeMetadata publicMetadata = Active(KeyKind.AsymmetricPublic, WellKnownCapabilities.VerifySignature);
        AsymmetricPublicKey publicKey = new(Logical, publicMetadata);
        Assert.That((await publicKey.ResolveForVerifySignatureAsync(Logical.AtVersion(new KeyVersion(1)))).Capability,
            Is.EqualTo(WellKnownCapabilities.VerifySignature));
        Assert.That(publicKey.Handle, Is.EqualTo(Logical));
        Assert.That(publicKey.ToString(), Is.EqualTo("AsymmetricPublicKey"));
        Assert.That(Assert.ThrowsAsync<KeyCapabilityException>(async () => await new AsymmetricPrivateKey(Logical, publicMetadata)
            .ResolveForSignAsync())!.Failure, Is.EqualTo(KeyCapabilityFailure.KindMismatch));
    }

    [Test]
    public void OrdinaryTypedViewsExposeNoRawKeyMaterial()
    {
        Type[] publicViews =
        [
            typeof(EncryptionKey),
            typeof(MacKey),
            typeof(DerivationKey),
            typeof(AsymmetricPrivateKey),
            typeof(AsymmetricPublicKey),
            typeof(KeyCapabilityResolution),
        ];

        foreach (Type view in publicViews)
        {
            Assert.That(view.GetProperties().Any(property => property.PropertyType == typeof(byte[])), Is.False,
                $"{view.Name} exposes a raw material property.");
            Assert.That(view.GetMethods().Any(method => method.ReturnType == typeof(byte[])), Is.False,
                $"{view.Name} exposes a raw material return value.");
        }
    }

    [Test]
    public void InvalidViewCreationRejectsNullResolverAndUndefinedHandle()
    {
        FakeMetadata metadata = Active(KeyKind.Symmetric, WellKnownCapabilities.Encrypt);
        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentException>(() => new EncryptionKey(default, metadata));
            Assert.Throws<ArgumentNullException>(() => new EncryptionKey(Logical, null!));
            Assert.Throws<ArgumentNullException>(() => new MacKey(Logical, null!));
            Assert.Throws<ArgumentNullException>(() => new DerivationKey(Logical, null!));
            Assert.Throws<ArgumentNullException>(() => new AsymmetricPrivateKey(Logical, null!));
            Assert.Throws<ArgumentNullException>(() => new AsymmetricPublicKey(Logical, null!));
        });
    }

    [Test]
    public void ErrorMessagesDoNotIncludePersistentIdentity()
    {
        FakeMetadata metadata = Active(KeyKind.Symmetric, WellKnownCapabilities.Decrypt);
        KeyCapabilityException exception = Assert.ThrowsAsync<KeyCapabilityException>(async () =>
            await new EncryptionKey(Logical, metadata).ResolveForEncryptAsync())!;
        Assert.Multiple(() =>
        {
            Assert.That(exception.Message, Does.Not.Contain(Provider.ToString()));
            Assert.That(exception.Message, Does.Not.Contain(Key.ToString()));
            Assert.That(exception.Failure, Is.EqualTo(KeyCapabilityFailure.CapabilityMissing));
        });
    }

    private sealed class FakeMetadata : IKeyMetadataResolver
    {
        private readonly ProviderId _provider;
        private readonly KeyId _key;
        private readonly KeyKind _kind;
        private readonly Dictionary<KeyReference, KeyVersionDescriptor> _versions = [];
        private KeyDescriptor _logical;

        internal FakeMetadata(ProviderId provider, KeyId key, KeyKind kind)
        {
            _provider = provider;
            _key = key;
            _kind = kind;
            _logical = new KeyDescriptor(provider, key, null, kind, LogicalKeyState.Retired, null);
        }

        internal int LogicalQueries { get; private set; }
        internal bool LogicalMissing { get; set; }
        internal bool ExactMissing { get; set; }
        internal bool ReturnWrongLogical { get; set; }
        internal bool ReturnWrongExact { get; set; }
        internal Action? OnLogicalRead { get; set; }

        internal void SetActive(long version, AlgorithmId algorithm, params CapabilityId[] capabilities)
        {
            KeyVersion v = new(version);
            _logical = new KeyDescriptor(_provider, _key, null, _kind, LogicalKeyState.Active, v);
            SetVersion(version, KeyVersionState.Active, algorithm, capabilities);
        }

        internal void SetVersion(long version, KeyVersionState state, AlgorithmId algorithm, params CapabilityId[] capabilities)
        {
            KeyReference reference = new(_provider, _key, new KeyVersion(version));
            _versions[reference] = new KeyVersionDescriptor(reference, state, algorithm, capabilities);
        }

        internal void Rotate(long version, AlgorithmId algorithm, params CapabilityId[] capabilities)
        {
            KeyVersion old = _logical.ActiveVersion!.Value;
            KeyVersionDescriptor descriptor = _versions[new KeyReference(_provider, _key, old)];
            SetVersion(old.Value, KeyVersionState.Retired, descriptor.Algorithm, [.. descriptor.Capabilities]);
            SetActive(version, algorithm, capabilities);
        }

        internal void Retire()
        {
            KeyVersion old = _logical.ActiveVersion!.Value;
            KeyVersionDescriptor descriptor = _versions[new KeyReference(_provider, _key, old)];
            SetVersion(old.Value, KeyVersionState.Retired, descriptor.Algorithm, [.. descriptor.Capabilities]);
            _logical = new KeyDescriptor(_provider, _key, null, _kind, LogicalKeyState.Retired, null);
        }

        internal void DeleteLogical() =>
            _logical = new KeyDescriptor(_provider, _key, null, _kind, LogicalKeyState.Deleted, null);

        public ValueTask<KeyDescriptor?> FindLogicalAsync(LogicalKeyHandle handle, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LogicalQueries++;
            KeyDescriptor? result = LogicalMissing ? null : ReturnWrongLogical
                ? new KeyDescriptor(_provider, OtherKey, null, _kind, LogicalKeyState.Active, new KeyVersion(1))
                : _logical;
            OnLogicalRead?.Invoke();
            return ValueTask.FromResult(result);
        }

        public ValueTask<KeyVersionDescriptor?> FindExactAsync(ExactKeyHandle handle, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ExactMissing || !_versions.TryGetValue(handle.Reference, out KeyVersionDescriptor? descriptor))
            {
                return ValueTask.FromResult<KeyVersionDescriptor?>(null);
            }

            if (ReturnWrongExact)
            {
                KeyReference wrong = new(_provider, OtherKey, handle.Reference.Version);
                return ValueTask.FromResult<KeyVersionDescriptor?>(new KeyVersionDescriptor(wrong, descriptor.State, descriptor.Algorithm, descriptor.Capabilities));
            }

            return ValueTask.FromResult<KeyVersionDescriptor?>(descriptor);
        }
    }
}
