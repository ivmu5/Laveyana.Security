using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Payloads;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Providers;
using Laveyana.Security.Signatures;
using Laveyana.Security.Software;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Phase 17 MAC/signature positives, historical verification and failure separation.</summary>
[TestFixture]
internal sealed class ManagedMacSignatureTests
{
    private static readonly ProviderId Provider = ProviderId.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly ProviderId ForeignProvider = ProviderId.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly byte[] Data = "versioned authentic message"u8.ToArray();

    private static async Task<(SoftwareKeyProviderBackend Backend, LogicalKeyHandle Handle)> MacAsync(
        AlgorithmId algorithm, params CapabilityId[] capabilities)
    {
        // Tests own their fake store and protector; caller receives a backend for short-lived fixtures.
        SoftwareKeyProviderBackend backend = new(Provider, new StorageContractsTests.MemoryStore(),
            new SoftwareKeyProviderTests.TestProtector());
        KeyDescriptor descriptor = await backend.CreateAsync(new KeyName("Mac"), algorithm,
            capabilities.Length == 0 ? [WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac] : capabilities);
        return (backend, new LogicalKeyHandle(descriptor.ProviderId, descriptor.KeyId));
    }

    [TestCase("hmac-sha-256", 32)]
    [TestCase("hmac-sha-384", 48)]
    [TestCase("hmac-sha-512", 64)]
    public async Task ComputeVerifyAndWireRoundTrip(string name, int length)
    {
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await MacAsync(new AlgorithmId(name));
        MacResult result = await backend.ComputeMacAsync(handle, Data);
        Assert.Multiple(() =>
        {
            Assert.That(result.ExportTagCopy(), Has.Length.EqualTo(length));
            Assert.That(result.Reference, Is.EqualTo(handle.AtVersion(new KeyVersion(1)).Reference));
            Assert.That(result.Algorithm, Is.EqualTo(new AlgorithmId(name)));
        });
        Assert.That(await backend.VerifyMacAsync(result, Data), Is.True);
        MacResult restored = ManagedPayloadCodec.DecodeMac(ManagedPayloadCodec.Encode(result));
        Assert.That(await backend.VerifyMacAsync(restored, Data), Is.True);
        Assert.That(await backend.VerifyMacAsync(result, "changed"u8.ToArray()), Is.False);
        byte[] corrupted = result.ExportTagCopy();
        corrupted[0] ^= 128;
        Assert.That(await backend.VerifyMacAsync(new MacResult(result.Reference, result.Algorithm, corrupted), Data), Is.False);
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        Assert.That(registry.RouteMac(handle), Is.SameAs(backend));
        Assert.That(registry.RouteMac(result.Reference), Is.SameAs(backend));
    }

    [Test]
    public async Task ProducedMacMatchesIndependentSha256OverStoredMaterial()
    {
        StorageContractsTests.MemoryStore store = new();
        using SoftwareKeyProviderTests.TestProtector protector = new();
        SoftwareKeyProviderBackend backend = new(Provider, store, protector);
        KeyDescriptor descriptor = await backend.CreateAsync(new KeyName("KnownProfile"),
            WellKnownAlgorithms.HmacSha256, [WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac]);
        LogicalKeyHandle handle = new(descriptor.ProviderId, descriptor.KeyId);
        MacResult result = await backend.ComputeMacAsync(handle, Data);
        KeyStoreEntry entry = (await store.FindByIdAsync(Provider, descriptor.KeyId))!;
        KeyStoreMaterialReadResult read = await store.ReadMaterialAsync(result.Reference, entry.Revision);
        Assert.That(read.Status, Is.EqualTo(KeyStoreMaterialReadStatus.Found));
        using SensitiveMaterialLease secret = await protector.UnprotectAsync(read.ProtectedMaterial!,
            ProtectionPurpose.KeyMaterial, KeyStoreProtectionContext.ForKeyMaterial(result.Reference));
        byte[]? independentlyComputed = null;
        try
        {
            secret.UseMaterial(material => independentlyComputed = HMACSHA256.HashData(material, Data));
            Assert.That(result.ExportTagCopy(), Is.EqualTo(independentlyComputed));
        }
        finally
        {
            if (independentlyComputed is not null)
            {
                CryptographicOperations.ZeroMemory(independentlyComputed);
            }
        }
    }

    [Test]
    public async Task RotationAndRetirementVerifyHistoricalMacUntilMaterialDeleted()
    {
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await MacAsync(WellKnownAlgorithms.HmacSha256);
        MacResult old = await backend.ComputeMacAsync(handle, Data);
        await backend.RotateAsync(handle);
        MacResult current = await backend.ComputeMacAsync(handle, Data);
        Assert.That(current.Reference.Version, Is.EqualTo(new KeyVersion(2)));
        Assert.That(await backend.VerifyMacAsync(old, Data), Is.True);
        await backend.RetireAsync(handle);
        Assert.That(await backend.VerifyMacAsync(old, Data), Is.True);
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.ComputeMacAsync(handle, Data));
        await backend.DeleteVersionAsync(handle, new KeyVersion(1), DateTimeOffset.UtcNow);
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.VerifyMacAsync(old, Data));
    }

    [Test]
    public async Task MissingCapabilityNeverReturnsFalseAsIfMismatched()
    {
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await MacAsync(
            WellKnownAlgorithms.HmacSha256, WellKnownCapabilities.Mac);
        MacResult value = await backend.ComputeMacAsync(handle, Data);
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.VerifyMacAsync(value, Data));
        (SoftwareKeyProviderBackend verifier, LogicalKeyHandle other) = await MacAsync(
            WellKnownAlgorithms.HmacSha256, WellKnownCapabilities.VerifyMac);
        Assert.ThrowsAsync<CryptographicException>(async () => await verifier.ComputeMacAsync(other, Data));
        Assert.ThrowsAsync<ArgumentException>(async () => await backend.VerifyMacAsync(
            new MacResult(new KeyReference(ForeignProvider, handle.KeyId, new KeyVersion(1)),
                WellKnownAlgorithms.HmacSha256, new byte[32]), Data));
    }

    [Test]
    public async Task CancellationAndTooLargeMacInputFailWithoutReturningFalse()
    {
        (SoftwareKeyProviderBackend backend, LogicalKeyHandle handle) = await MacAsync(WellKnownAlgorithms.HmacSha256);
        using CancellationTokenSource canceled = new();
        await canceled.CancelAsync();
        Assert.ThrowsAsync<OperationCanceledException>(async () => await backend.ComputeMacAsync(handle, Data, canceled.Token));
        Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await backend.ComputeMacAsync(handle, new byte[16 * 1024 * 1024 + 1]));
    }

    [Test]
    public async Task EcdsaP256RoundTripTamperAndHistoricalVerification()
    {
        using EphemeralSignatureKeyOperations keys = new();
        SignatureMetadata metadata = new(WellKnownAlgorithms.EcdsaP256Sha256);
        ECDsa firstKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa externalVerifier = ECDsa.Create(firstKey.ExportParameters(false));
        keys.AddEcdsa(metadata.Ref(1), firstKey);
        keys.AddEcdsa(metadata.Ref(2), ECDsa.Create(ECCurve.NamedCurves.nistP256));
        ManagedSignatureBackend backend = new(metadata, keys);
        SignaturePayload old = await backend.SignAsync(metadata.Handle, Data);
        Assert.That(old.ExportSignatureCopy(), Has.Length.EqualTo(64));
        Assert.That(externalVerifier.VerifyData(Data, old.ExportSignatureCopy(), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation), Is.True);
        Assert.That(await backend.VerifySignatureAsync(old, Data), Is.True);
        Assert.That(await backend.VerifySignatureAsync(old, "tampered"u8.ToArray()), Is.False);
        byte[] altered = old.ExportSignatureCopy(); altered[0] ^= 1;
        Assert.That(await backend.VerifySignatureAsync(new SignaturePayload(old.Reference, old.Algorithm, altered), Data), Is.False);
        metadata.Active = new KeyVersion(2);
        SignaturePayload current = await backend.SignAsync(metadata.Handle, Data);
        Assert.That(current.Reference.Version, Is.EqualTo(new KeyVersion(2)));
        Assert.That(await backend.VerifySignatureAsync(old, Data), Is.True);
        SignaturePayload wrongVersion = new(metadata.Ref(2), old.Algorithm, old.ExportSignatureCopy());
        Assert.That(await backend.VerifySignatureAsync(wrongVersion, Data), Is.False);
        metadata.BlockOld = true;
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.VerifySignatureAsync(old, Data));
        Assert.That(await backend.VerifySignatureAsync(current, Data), Is.True);
    }

    [Test]
    public async Task RsaPss3072UsesExactAlgorithmAndCanonicalEncoding()
    {
        using EphemeralSignatureKeyOperations keys = new();
        SignatureMetadata metadata = new(WellKnownAlgorithms.RsaPssSha256);
        keys.AddRsa(metadata.Ref(1), RSA.Create(3072));
        ManagedSignatureBackend backend = new(metadata, keys);
        SignaturePayload value = await backend.SignAsync(metadata.Handle, Data);
        Assert.That(value.ExportSignatureCopy(), Has.Length.EqualTo(384));
        Assert.That(value.Encoding, Is.EqualTo("rsa-pss-raw"));
        Assert.That(await backend.VerifySignatureAsync(value, Data), Is.True);
        Assert.That(await backend.VerifySignatureAsync(value, "wrong"u8.ToArray()), Is.False);
        Assert.That(await backend.VerifySignatureAsync(ManagedPayloadCodec.DecodeSignature(
            ManagedPayloadCodec.Encode(value)), Data), Is.True);
    }

    [Test]
    public async Task SigningFailsOnWrongKindMissingCapabilityOrRevokedState()
    {
        using EphemeralSignatureKeyOperations keys = new();
        SignatureMetadata metadata = new(WellKnownAlgorithms.EcdsaP256Sha256);
        keys.AddEcdsa(metadata.Ref(1), ECDsa.Create(ECCurve.NamedCurves.nistP256));
        ManagedSignatureBackend backend = new(metadata, keys);
        SignaturePayload value = await backend.SignAsync(metadata.Handle, Data);
        metadata.Kind = KeyKind.AsymmetricPublic;
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.SignAsync(metadata.Handle, Data));
        Assert.That(await backend.VerifySignatureAsync(value, Data), Is.True);
        metadata.AllowVerify = false;
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.VerifySignatureAsync(value, Data));
        metadata.AllowVerify = true;
        metadata.Kind = KeyKind.AsymmetricPrivate;
        metadata.AllowSign = false;
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.SignAsync(metadata.Handle, Data));
        metadata.AllowSign = true;
        metadata.Active = null;
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.SignAsync(metadata.Handle, Data));
    }

    [Test]
    public async Task TypedViewsDoNotAllowCrossKeySignatureOrMacVerification()
    {
        (SoftwareKeyProviderBackend macBackend, LogicalKeyHandle macHandle) = await MacAsync(
            WellKnownAlgorithms.HmacSha256);
        MacKey typedMac = new(macHandle, macBackend);
        MacResult mac = await typedMac.ComputeMacAsync(macBackend, Data);
        Assert.That(await typedMac.VerifyMacAsync(macBackend, mac, Data), Is.True);
        MacKey wrongMac = new(new LogicalKeyHandle(Provider, KeyId.New()), macBackend);
        Assert.ThrowsAsync<ArgumentException>(async () => await wrongMac.VerifyMacAsync(macBackend, mac, Data));

        using EphemeralSignatureKeyOperations keys = new();
        SignatureMetadata metadata = new(WellKnownAlgorithms.EcdsaP256Sha256);
        keys.AddEcdsa(metadata.Ref(1), ECDsa.Create(ECCurve.NamedCurves.nistP256));
        ManagedSignatureBackend signing = new(metadata, keys);
        AsymmetricPrivateKey privateKey = new(metadata.Handle, signing);
        SignaturePayload payload = await privateKey.SignAsync(signing, Data);
        metadata.Kind = KeyKind.AsymmetricPublic;
        AsymmetricPublicKey publicKey = new(metadata.Handle, signing);
        Assert.That(await publicKey.VerifySignatureAsync(signing, payload, Data), Is.True);
        AsymmetricPublicKey wrongPublic = new(new LogicalKeyHandle(Provider, KeyId.New()), signing);
        Assert.ThrowsAsync<ArgumentException>(async () => await wrongPublic.VerifySignatureAsync(signing, payload, Data));
    }

    [Test]
    public async Task MissingPrivateKeyAndProviderFailureNeverBecomeInvalidSignature()
    {
        using EphemeralSignatureKeyOperations keys = new();
        SignatureMetadata metadata = new(WellKnownAlgorithms.EcdsaP256Sha256);
        ManagedSignatureBackend backend = new(metadata, keys);
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.SignAsync(metadata.Handle, Data));
        SignaturePayload forged = new(metadata.Ref(1), metadata.Algorithm, new byte[64]);
        Assert.ThrowsAsync<CryptographicException>(async () => await backend.VerifySignatureAsync(forged, Data));
        ProviderRegistry registry = new([new ProviderRegistration(backend)]);
        Assert.That(registry.RouteSignature(metadata.Handle), Is.SameAs(backend));
        Assert.That(registry.RouteSignature(forged.Reference), Is.SameAs(backend));
        Assert.Throws<KeyNotFoundException>(() => registry.RouteSignature(
            new KeyReference(ForeignProvider, metadata.Handle.KeyId, new KeyVersion(1))));
    }

    [Test]
    public async Task SignatureExecutorFailureAndCancellationRemainExceptions()
    {
        SignatureMetadata metadata = new(WellKnownAlgorithms.EcdsaP256Sha256);
        ManagedSignatureBackend backend = new(metadata, new ThrowingSignatureKeys());
        Assert.ThrowsAsync<IOException>(async () => await backend.SignAsync(metadata.Handle, Data));
        SignaturePayload value = new(metadata.Ref(1), metadata.Algorithm, new byte[64]);
        Assert.ThrowsAsync<IOException>(async () => await backend.VerifySignatureAsync(value, Data));
        using CancellationTokenSource canceled = new();
        await canceled.CancelAsync();
        Assert.ThrowsAsync<OperationCanceledException>(async () => await backend.SignAsync(
            metadata.Handle, Data, canceled.Token));
    }

    [Test]
    public async Task SigningAndVerificationFreezeCallerMessageBeforeMetadataAwaits()
    {
        using EphemeralSignatureKeyOperations keys = new();
        SignatureMetadata metadata = new(WellKnownAlgorithms.EcdsaP256Sha256);
        keys.AddEcdsa(metadata.Ref(1), ECDsa.Create(ECCurve.NamedCurves.nistP256));
        ManagedSignatureBackend direct = new(metadata, keys);
        byte[] intended = "immutable-call-input"u8.ToArray();
        PausedSignatureMetadata pausedSign = new(metadata);
        ManagedSignatureBackend signing = new(pausedSign, keys);
        byte[] mutableSignInput = (byte[])intended.Clone();
        Task<SignaturePayload> pendingSign = signing.SignAsync(metadata.Handle, mutableSignInput).AsTask();
        await pausedSign.WaitUntilEnteredAsync();
        mutableSignInput[0] ^= 0xff;
        pausedSign.Release();
        SignaturePayload signature = await pendingSign;
        Assert.That(await direct.VerifySignatureAsync(signature, intended), Is.True);
        Assert.That(await direct.VerifySignatureAsync(signature, mutableSignInput), Is.False);

        PausedSignatureMetadata pausedVerify = new(metadata);
        ManagedSignatureBackend verifier = new(pausedVerify, keys);
        byte[] mutableVerifyInput = (byte[])intended.Clone();
        Task<bool> pendingVerify = verifier.VerifySignatureAsync(signature, mutableVerifyInput).AsTask();
        await pausedVerify.WaitUntilEnteredAsync();
        mutableVerifyInput[0] ^= 0xff;
        pausedVerify.Release();
        Assert.That(await pendingVerify, Is.True);
    }

    /// <summary>Suspends metadata lookup to reproduce changes to caller-owned input after call entry.</summary>
    private sealed class PausedSignatureMetadata(IKeyProviderBackend inner) : IKeyProviderBackend
    {
        private readonly TaskCompletionSource<bool> _entered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> _resume =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ProviderId ProviderId => inner.ProviderId;

        public Task WaitUntilEnteredAsync() => _entered.Task.WaitAsync(TimeSpan.FromSeconds(10));

        public void Release() => _resume.TrySetResult(true);

        public ValueTask<ProviderCapabilitySnapshot> GetCapabilitiesAsync(CancellationToken c = default) =>
            inner.GetCapabilitiesAsync(c);

        public async ValueTask<KeyDescriptor?> FindLogicalAsync(LogicalKeyHandle handle,
            CancellationToken c = default)
        {
            _entered.TrySetResult(true);
            await _resume.Task.WaitAsync(c).ConfigureAwait(false);
            return await inner.FindLogicalAsync(handle, c).ConfigureAwait(false);
        }

        public ValueTask<KeyVersionDescriptor?> FindExactAsync(ExactKeyHandle handle,
            CancellationToken c = default) => inner.FindExactAsync(handle, c);
    }

    private sealed class ThrowingSignatureKeys : IVersionedSignatureKeyOperations
    {
        public ValueTask<byte[]> SignAsync(KeyReference reference, AlgorithmId algorithm,
            ReadOnlyMemory<byte> message, CancellationToken cancellationToken = default) =>
            ValueTask.FromException<byte[]>(new IOException("Injected signer failure."));

        public ValueTask<bool> VerifyAsync(KeyReference reference, AlgorithmId algorithm,
            ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> signature,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<bool>(new IOException("Injected verifier failure."));
    }

    private sealed class SignatureMetadata(AlgorithmId algorithm) : IKeyProviderBackend
    {
        public ProviderId ProviderId => Provider;
        public AlgorithmId Algorithm { get; } = algorithm;
        public LogicalKeyHandle Handle { get; } = new(Provider, KeyId.New());
        public KeyVersion? Active { get; set; } = new KeyVersion(1);
        public KeyKind Kind { get; set; } = KeyKind.AsymmetricPrivate;
        public bool BlockOld { get; set; }
        public bool AllowSign { get; set; } = true;
        public bool AllowVerify { get; set; } = true;
        public KeyReference Ref(int version) => new(Provider, Handle.KeyId, new KeyVersion(version));

        public ValueTask<ProviderCapabilitySnapshot> GetCapabilitiesAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new ProviderCapabilitySnapshot(Provider, [WellKnownCapabilities.Sign, WellKnownCapabilities.VerifySignature]));

        public ValueTask<KeyDescriptor?> FindLogicalAsync(LogicalKeyHandle handle, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<KeyDescriptor?>(handle == Handle ? new KeyDescriptor(Provider, Handle.KeyId,
                null, Kind, Active.HasValue ? LogicalKeyState.Active : LogicalKeyState.Retired, Active) : null);

        public ValueTask<KeyVersionDescriptor?> FindExactAsync(ExactKeyHandle handle, CancellationToken cancellationToken = default)
        {
            if (handle.Reference.KeyId != Handle.KeyId || handle.Reference.ProviderId != Provider)
            {
                return ValueTask.FromResult<KeyVersionDescriptor?>(null);
            }
            bool isOld = handle.Reference.Version == new KeyVersion(1);
            KeyVersionState state = isOld && BlockOld ? KeyVersionState.Deleted :
                Active == handle.Reference.Version ? KeyVersionState.Active : KeyVersionState.Retired;
            List<CapabilityId> capabilities = [];
            if (AllowSign)
            {
                capabilities.Add(WellKnownCapabilities.Sign);
            }
            if (AllowVerify)
            {
                capabilities.Add(WellKnownCapabilities.VerifySignature);
            }
            return ValueTask.FromResult<KeyVersionDescriptor?>(new KeyVersionDescriptor(handle.Reference, state,
                Algorithm, capabilities));
        }
    }
}
