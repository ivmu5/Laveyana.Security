using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Maui.NativeKeys;
using NUnit.Framework;

namespace Laveyana.Security.Tests.Maui;

[TestFixture]
public sealed class NativeSigningKeyContractTests
{
    [Test]
    public void NativeKeyInfoDefensivelyCopiesPublicKey()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] input = key.ExportSubjectPublicKeyInfo();
        byte[] original = (byte[])input.Clone();
        ProviderId providerId = ProviderId.New();
        NativeSigningKeyInfo info = new(providerId, KeyId.New(), input);
        Assert.That(info.ProviderId, Is.EqualTo(providerId));
        input[0] ^= 1;
        byte[] exported = info.ExportSubjectPublicKeyInfo();
        Assert.That(exported, Is.EqualTo(original));
        exported[1] ^= 1;
        Assert.That(info.ExportSubjectPublicKeyInfo(), Is.EqualTo(original));
    }

    [Test]
    public void NativeKeyInfoRejectsMalformedPublicKey()
    {
        Assert.Throws<CryptographicException>(() => new NativeSigningKeyInfo(ProviderId.New(), KeyId.New(), [1, 2, 3]));
    }

    [Test]
    public void NativeKeyInfoRejectsOtherCurve()
    {
        using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<CryptographicException>(() =>
            new NativeSigningKeyInfo(ProviderId.New(), KeyId.New(), p384.ExportSubjectPublicKeyInfo()));
    }

    [Test]
    public void NativeKeyInfoRequiresInitializedIdentity()
    {
        using ECDsa source = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] spki = source.ExportSubjectPublicKeyInfo();
        Assert.Throws<ArgumentException>(() => new NativeSigningKeyInfo(default, KeyId.New(), spki));
        Assert.Throws<ArgumentException>(() => new NativeSigningKeyInfo(ProviderId.New(), default, spki));
    }

    [Test]
    public async Task WindowsTpmRoundTripRequiresExplicitOptIn()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows TPM integration requires a Windows host.");
            return;
        }

        if (Environment.GetEnvironmentVariable("LAVEYANA_RUN_TPM_TESTS") != "1")
        {
            Assert.Ignore("Real TPM test is opt-in and requires compatible Windows hardware.");
        }

        ProviderId providerId = ProviderId.New();
        WindowsTpmSigningKeyService provider = new(providerId);
        KeyId keyId = KeyId.New();
        bool created = false;
        try
        {
            NativeSigningKeyInfo createdInfo = await provider.CreateAsync(keyId);
            created = true;
            // Reopen the persistent key through a separate provider instance.
            WindowsTpmSigningKeyService reopened = new(providerId);
            NativeSigningKeyInfo? found = await reopened.FindAsync(keyId);
            Assert.That(found, Is.Not.Null);
            Assert.That(found!.ProviderId, Is.EqualTo(providerId));
            Assert.That(found.KeyId, Is.EqualTo(keyId));
            Assert.That(createdInfo.ProviderId, Is.EqualTo(providerId));
            byte[] publicKey = createdInfo.ExportSubjectPublicKeyInfo();
            Assert.That(found.ExportSubjectPublicKeyInfo(), Is.EqualTo(publicKey));

            // A duplicate create must not silently replace the key.
            Assert.ThrowsAsync<CryptographicException>(async () => await reopened.CreateAsync(keyId));
            Assert.That((await reopened.FindAsync(keyId))!.ExportSubjectPublicKeyInfo(), Is.EqualTo(publicKey));

            byte[] message = "native-test"u8.ToArray();
            byte[] signature = await reopened.SignAsync(keyId, message);
            using ECDsa verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(found.ExportSubjectPublicKeyInfo(), out _);
            Assert.That(verifier.VerifyData(message, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation), Is.True);
            Assert.That(verifier.VerifyData("different-message"u8, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation), Is.False);

            await reopened.DeleteAsync(keyId);
            created = false;
            Assert.That(await provider.FindAsync(keyId), Is.Null);
        }
        finally
        {
            if (created)
            {
                await provider.DeleteAsync(keyId);
            }
        }
    }
}
