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
        NativeSigningKeyInfo info = new(KeyId.New(), input);
        input[0] ^= 1;
        byte[] exported = info.ExportSubjectPublicKeyInfo();
        Assert.That(exported, Is.EqualTo(original));
        exported[1] ^= 1;
        Assert.That(info.ExportSubjectPublicKeyInfo(), Is.EqualTo(original));
    }

    [Test]
    public void NativeKeyInfoRejectsMalformedPublicKey()
    {
        Assert.Throws<CryptographicException>(() => new NativeSigningKeyInfo(KeyId.New(), [1, 2, 3]));
    }

    [Test]
    public void NativeKeyInfoRejectsOtherCurve()
    {
        using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<CryptographicException>(() =>
            new NativeSigningKeyInfo(KeyId.New(), p384.ExportSubjectPublicKeyInfo()));
    }

    [Test]
    public void NativeKeyInfoRequiresInitializedIdentity()
    {
        Assert.Throws<ArgumentException>(() => new NativeSigningKeyInfo(default, [1, 2]));
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

        WindowsTpmSigningKeyService provider = new(ProviderId.New());
        KeyId keyId = KeyId.New();
        bool created = false;
        try
        {
            NativeSigningKeyInfo createdInfo = await provider.CreateAsync(keyId);
            created = true;
            NativeSigningKeyInfo? found = await provider.FindAsync(keyId);
            Assert.That(found, Is.Not.Null);
            Assert.That(found!.ExportSubjectPublicKeyInfo(),
                Is.EqualTo(createdInfo.ExportSubjectPublicKeyInfo()));

            byte[] message = "native-test"u8.ToArray();
            byte[] signature = await provider.SignAsync(keyId, message);
            using ECDsa verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(found.ExportSubjectPublicKeyInfo(), out _);
            Assert.That(verifier.VerifyData(message, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation), Is.True);
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
