using System.Security.Cryptography;
using System.Text.Json;
using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Agreement;
using Laveyana.Security.Providers;
using Laveyana.Security.Software;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Phase 18 ECDH-HKDF, symmetric derivation, purpose isolation, zeroization and revocation.</summary>
[TestFixture]
internal sealed class KeyAgreementDerivationTests
{
    private static readonly ProviderId Owner = ProviderId.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly byte[] AppContext = "example-protocol-v1"u8.ToArray();
    private static readonly byte[] KnownD0 = Convert.FromHexString(
        "0000000000000000000000000000000000000000000000000000000001000001");
    private static readonly byte[] KnownD1 = Convert.FromHexString(
        "0000000000000000000000000000000000000000000000000000000002000002");
    private static readonly byte[] KnownX0 = Convert.FromHexString(
        "640b4a1bc59f9df61aac80a8563d5af9e41a7c7296851b634edd6834f2c616ca");
    private static readonly byte[] KnownY0 = Convert.FromHexString(
        "105e7ddf0a0a24d27aa65aac16193f1b6e0981fb817d6adf96500280e82889d5");
    private static readonly byte[] KnownX1 = Convert.FromHexString(
        "516e3e76bec823efa375f2149e7448abe84b983131c5302bdb3afe3cddd4b46b");
    private static readonly byte[] KnownY1 = Convert.FromHexString(
        "908d1589a20d32b330ddc264e6991471f43c399ee965802c34cddd726dbbefc4");

    private static ECDiffieHellman KnownKey(byte[] d, byte[] x, byte[] y) =>
        ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = d,
            Q = new ECPoint { X = x, Y = y }
        });

    [Test]
    public async Task IndependentP256HkdfVectorMatchesAndBothPartiesAgree()
    {
        using EphemeralEcdhKeyOperations keys = new();
        KeyReference a = new(Owner, KeyId.New(), new KeyVersion(1));
        KeyReference b = new(Owner, KeyId.New(), new KeyVersion(1));
        byte[] apub = keys.Add(a, KnownKey(KnownD0, KnownX0, KnownY0));
        byte[] bpub = keys.Add(b, KnownKey(KnownD1, KnownX1, KnownY1));
        DerivationContext context = new("session-data", AppContext);
        using DerivedKeyLease first = await keys.AgreeAsync(a, WellKnownAlgorithms.EcdhP256, bpub, context);
        using DerivedKeyLease second = await keys.AgreeAsync(b, WellKnownAlgorithms.EcdhP256, apub, context);
        byte[] known = Convert.FromHexString("7cf5e2d15c63de865a4eda34c2de87d6ec5637f90e21fef990e74933fbe570aa");
        first.UseMaterial(x => Assert.That(x.SequenceEqual(known), Is.True));
        second.UseMaterial(x => Assert.That(x.SequenceEqual(known), Is.True));
        Assert.That(first.Source, Is.EqualTo(a));
        Assert.That(second.Source, Is.EqualTo(b));
    }

    [Test]
    public async Task DifferentPurposesContextsAndLengthsProduceDifferentResults()
    {
        using EphemeralEcdhKeyOperations keys = new();
        KeyReference local = new(Owner, KeyId.New(), new KeyVersion(1));
        keys.Add(local, ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256));
        using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] pub = peer.ExportSubjectPublicKeyInfo();
        using DerivedKeyLease data = await keys.AgreeAsync(local, WellKnownAlgorithms.EcdhP256,
            pub, new DerivationContext("data", AppContext));
        using DerivedKeyLease other = await keys.AgreeAsync(local, WellKnownAlgorithms.EcdhP256,
            pub, new DerivationContext("metadata", AppContext));
        using DerivedKeyLease changed = await keys.AgreeAsync(local, WellKnownAlgorithms.EcdhP256,
            pub, new DerivationContext("data", "different-context"u8));
        using DerivedKeyLease longer = await keys.AgreeAsync(local, WellKnownAlgorithms.EcdhP256,
            pub, new DerivationContext("data", AppContext, 48));
        byte[]? first = null;
        data.UseMaterial(value => first = value.ToArray());
        try
        {
            other.UseMaterial(value => Assert.That(value.SequenceEqual(first), Is.False));
            changed.UseMaterial(value => Assert.That(value.SequenceEqual(first), Is.False));
            longer.UseMaterial(value => Assert.That(value.Length, Is.EqualTo(48)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first!);
        }
    }

    [Test]
    public async Task RevokedKeyWrongCurveSelfAgreementAndTrailingSpkiFailClosed()
    {
        using EphemeralEcdhKeyOperations keys = new();
        KeyReference a = new(Owner, KeyId.New(), new KeyVersion(1));
        byte[] apub = keys.Add(a, ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256));
        DerivationContext context = new("message", AppContext);
        Assert.ThrowsAsync<CryptographicException>(async () => await keys.AgreeAsync(a, WellKnownAlgorithms.EcdhP256, apub, context));
        using ECDiffieHellman p384 = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
        Assert.ThrowsAsync<CryptographicException>(async () => await keys.AgreeAsync(a, WellKnownAlgorithms.EcdhP256,
            p384.ExportSubjectPublicKeyInfo(), context));
        using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] trailing = [..peer.ExportSubjectPublicKeyInfo(), 0];
        Assert.ThrowsAsync<CryptographicException>(async () => await keys.AgreeAsync(a, WellKnownAlgorithms.EcdhP256,
            trailing, context));
        keys.Revoke(a);
        Assert.ThrowsAsync<CryptographicException>(async () => await keys.AgreeAsync(a, WellKnownAlgorithms.EcdhP256,
            peer.ExportSubjectPublicKeyInfo(), context));
    }

    [Test]
    public void OwnedMaterialIsZeroedAfterDisposeAndNoDefaultExportOrJson()
    {
        byte[] owned = Enumerable.Repeat((byte)0xA4, 32).ToArray();
        DerivedKeyLease key = new(new KeyReference(Owner, KeyId.New(), new KeyVersion(1)), "data", owned);
        Assert.That(key.ToString(), Does.Not.Contain("a4"));
        Assert.Throws<CryptographicException>(() => key.ExportMaterialCopy(new NeverExport()));
        Assert.Throws<NotSupportedException>(() => JsonSerializer.Serialize(key));
        byte[] explicitCopy = key.ExportMaterialCopy(new PermitExport());
        Assert.That(explicitCopy, Is.EqualTo(Enumerable.Repeat((byte)0xA4, 32)));
        key.Dispose();
        Assert.That(owned, Is.EqualTo(new byte[32]));
        Assert.Throws<ObjectDisposedException>(() => key.UseMaterial(_ => { }));
        Assert.That(explicitCopy[0], Is.EqualTo(0xA4));
        CryptographicOperations.ZeroMemory(explicitCopy);
    }

    [Test]
    public void ContextRejectsInvalidPurposeSizeAndUnsupportedBounds()
    {
        Assert.Throws<ArgumentException>(() => new DerivationContext("", AppContext));
        Assert.Throws<ArgumentException>(() => new DerivationContext("UPPER", AppContext));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DerivationContext("ok", []));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DerivationContext("ok", AppContext, 12));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DerivationContext("ok", AppContext, 65));
    }

    [Test]
    public async Task BackendVerifiesActiveExactIdentityCapabilityAndRevocation()
    {
        using EphemeralEcdhKeyOperations executor = new();
        AgreementMetadata metadata = new();
        executor.Add(metadata.Reference, ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256));
        ManagedKeyAgreementBackend backend = new(metadata, executor);
        using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        DerivationContext context = new("transport", AppContext);
        using DerivedKeyLease derived = await backend.AgreeAsync(metadata.Handle, peer.ExportSubjectPublicKeyInfo(), context);
        Assert.That(derived.Length, Is.EqualTo(32));
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        Assert.That(registry.RouteAgreement(metadata.Handle), Is.SameAs(backend));
        metadata.AllowAgreement = false;
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.AgreeAsync(metadata.Handle,
            peer.ExportSubjectPublicKeyInfo(), context));
        metadata.AllowAgreement = true;
        metadata.State = KeyVersionState.Retired;
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.AgreeAsync(metadata.Handle,
            peer.ExportSubjectPublicKeyInfo(), context));
        metadata.State = KeyVersionState.Active;
        metadata.LogicalState = LogicalKeyState.Retired;
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.AgreeAsync(metadata.Handle,
            peer.ExportSubjectPublicKeyInfo(), context));
    }

    [Test]
    public async Task ExecutorCannotSubstituteASecretOrDifferentReference()
    {
        AgreementMetadata metadata = new();
        ManagedKeyAgreementBackend backend = new(metadata, new WrongAgreementResult());
        using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        DerivationContext context = new("transport", AppContext);
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.AgreeAsync(metadata.Handle,
            peer.ExportSubjectPublicKeyInfo(), context));
    }

    [Test]
    public async Task SymmetricHkdfUsesProtectedKeyAndRotationChangesExactSource()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderBackend backend = new(Owner, store, protector);
        KeyDescriptor logical = await backend.CreateAsync(new KeyName("Derivation"),
            WellKnownAlgorithms.HkdfSha256, [WellKnownCapabilities.Derive]);
        LogicalKeyHandle handle = new(Owner, logical.KeyId);
        DerivationContext context = new("session-data", AppContext);
        using DerivedKeyLease first = await backend.DeriveAsync(handle, context);
        using DerivedKeyLease same = await backend.DeriveAsync(handle, context);
        byte[]? value = null;
        first.UseMaterial(span => value = span.ToArray());
        try
        {
            same.UseMaterial(span => Assert.That(span.SequenceEqual(value), Is.True));
            Assert.That(first.Source.Version, Is.EqualTo(new KeyVersion(1)));
            await backend.RotateAsync(handle);
            using DerivedKeyLease second = await backend.DeriveAsync(handle, context);
            Assert.That(second.Source.Version, Is.EqualTo(new KeyVersion(2)));
            second.UseMaterial(span => Assert.That(span.SequenceEqual(value), Is.False));
            ProviderRegistry registry = new([new ProviderRegistration(backend)]);
            Assert.That(registry.RouteDerivation(handle), Is.SameAs(backend));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value!);
        }
    }

    [Test]
    public async Task CancellationAndUnavailableOperationRemainExceptions()
    {
        AgreementMetadata metadata = new();
        ManagedKeyAgreementBackend backend = new(metadata, new WrongAgreementResult());
        using CancellationTokenSource cts = new();
        await cts.CancelAsync();
        using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        Assert.ThrowsAsync<OperationCanceledException>(async () => await backend.AgreeAsync(metadata.Handle,
            peer.ExportSubjectPublicKeyInfo(), new DerivationContext("data", AppContext), cts.Token));
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderBackend symmetric = new(Owner, store, protector);
        Assert.ThrowsAsync<SoftwareKeyConflictException>(async () => await symmetric.DeriveAsync(
            new LogicalKeyHandle(Owner, KeyId.New()), new DerivationContext("data", AppContext)));
    }

    private sealed class NeverExport : IDerivedMaterialExportPolicy
    {
        public bool IsExportAllowed(KeyReference source, string purpose) => false;
    }
    private sealed class PermitExport : IDerivedMaterialExportPolicy
    {
        public bool IsExportAllowed(KeyReference source, string purpose) => true;
    }
    private sealed class WrongAgreementResult : IVersionedKeyAgreementOperations
    {
        public ValueTask<DerivedKeyLease> AgreeAsync(KeyReference reference, AlgorithmId algorithm,
            ReadOnlyMemory<byte> peerPublicKeySpki, DerivationContext context,
            CancellationToken cancellationToken = default) => ValueTask.FromResult(
                new DerivedKeyLease(new KeyReference(reference.ProviderId, KeyId.New(), reference.Version),
                    context.Purpose, new byte[context.OutputLength]));
    }
    private sealed class AgreementMetadata : IKeyProviderBackend
    {
        public ProviderId ProviderId => Owner;
        public LogicalKeyHandle Handle { get; } = new(Owner, KeyId.New());
        public KeyReference Reference => new(Owner, Handle.KeyId, new KeyVersion(1));
        public bool AllowAgreement { get; set; } = true;
        public KeyVersionState State { get; set; } = KeyVersionState.Active;
        public LogicalKeyState LogicalState { get; set; } = LogicalKeyState.Active;
        public ValueTask<ProviderCapabilitySnapshot> GetCapabilitiesAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new ProviderCapabilitySnapshot(Owner,
                AllowAgreement ? [WellKnownCapabilities.KeyAgreement] : []));
        public ValueTask<KeyDescriptor?> FindLogicalAsync(LogicalKeyHandle handle,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<KeyDescriptor?>(handle == Handle ?
                new KeyDescriptor(Owner, Handle.KeyId, null, KeyKind.AsymmetricPrivate, LogicalState,
                    LogicalState == LogicalKeyState.Active ? new KeyVersion(1) : null) : null);
        public ValueTask<KeyVersionDescriptor?> FindExactAsync(ExactKeyHandle handle,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<KeyVersionDescriptor?>(handle.Reference == Reference ?
                new KeyVersionDescriptor(Reference, State, WellKnownAlgorithms.EcdhP256,
                    AllowAgreement ? [WellKnownCapabilities.KeyAgreement] : []) : null);
    }
}
