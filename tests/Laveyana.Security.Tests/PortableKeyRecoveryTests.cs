using System.Security.Cryptography;
using System.Text;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Recovery;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

[TestFixture]
internal sealed class PortableKeyRecoveryTests
{
    private static byte[] Scope(string keyVersion = "v1") =>
        Encoding.UTF8.GetBytes("com.example.application|database-key|exact-key-id|" + keyVersion);

    [Test]
    public void RoundTripRestoresExactMaterialWithoutConsumingInputs()
    {
        byte[] original = RandomNumberGenerator.GetBytes(32);
        using SensitiveMaterialLease key = SensitiveMaterialLease.CreateCopy(original);
        using SensitiveMaterialLease recoverySecret = PortableKeyRecovery.GenerateRecoverySecret();

        byte[] encoded = PortableKeyRecovery.Protect(key, recoverySecret, Scope());
        using SensitiveMaterialLease restored = PortableKeyRecovery.Unprotect(encoded, recoverySecret, Scope());
        byte[]? observed = null;
        restored.UseMaterial(value => observed = value.ToArray());

        Assert.That(observed, Is.EqualTo(original));
        Assert.That(encoded, Has.Length.EqualTo(54 + original.Length + 16));
        Assert.That(key.Length, Is.EqualTo(32));
        Assert.That(recoverySecret.Length, Is.EqualTo(PortableKeyRecovery.RecoverySecretLength));
        CryptographicOperations.ZeroMemory(original);
        CryptographicOperations.ZeroMemory(observed!);
    }

    [Test]
    public void WrongRecoverySecretMustNotReleasePlaintext()
    {
        using SensitiveMaterialLease material = SensitiveMaterialLease.CreateCopy("sensitive-value"u8);
        using SensitiveMaterialLease original = PortableKeyRecovery.GenerateRecoverySecret();
        using SensitiveMaterialLease wrong = PortableKeyRecovery.GenerateRecoverySecret();
        byte[] encoded = PortableKeyRecovery.Protect(material, original, Scope());

        Assert.Throws<CryptographicException>(() => PortableKeyRecovery.Unprotect(encoded, wrong, Scope()));
    }

    [Test]
    public void WrongKeyVersionScopeMustNotReleasePlaintext()
    {
        using SensitiveMaterialLease material = SensitiveMaterialLease.CreateCopy("secret"u8);
        using SensitiveMaterialLease recoverySecret = PortableKeyRecovery.GenerateRecoverySecret();
        byte[] encoded = PortableKeyRecovery.Protect(material, recoverySecret, Scope());

        Assert.Throws<CryptographicException>(() =>
            PortableKeyRecovery.Unprotect(encoded, recoverySecret, Scope("v2")));
    }

    [Test]
    public void HeaderCiphertextAndTagModificationAreRejected()
    {
        using SensitiveMaterialLease material = SensitiveMaterialLease.CreateCopy("value"u8);
        using SensitiveMaterialLease recoverySecret = PortableKeyRecovery.GenerateRecoverySecret();
        byte[] encoded = PortableKeyRecovery.Protect(material, recoverySecret, Scope());
        foreach (int offset in new[] { 10, 42, 54, encoded.Length - 1 })
        {
            byte[] corrupted = (byte[])encoded.Clone();
            corrupted[offset] ^= 0x01;
            Assert.Throws<CryptographicException>(() =>
                PortableKeyRecovery.Unprotect(corrupted, recoverySecret, Scope()),
                "Unexpected success for tampered byte at offset " + offset);
        }
    }

    [Test]
    public void UnsupportedVersionAndTruncationAreRejectedBeforeAuthentication()
    {
        using SensitiveMaterialLease material = SensitiveMaterialLease.CreateCopy("value"u8);
        using SensitiveMaterialLease recoverySecret = PortableKeyRecovery.GenerateRecoverySecret();
        byte[] encoded = PortableKeyRecovery.Protect(material, recoverySecret, Scope());
        byte[] version = (byte[])encoded.Clone();
        version[4] = 2;
        Assert.Throws<InvalidDataException>(() =>
            PortableKeyRecovery.Unprotect(version, recoverySecret, Scope()));
        Assert.Throws<InvalidDataException>(() =>
            PortableKeyRecovery.Unprotect(encoded.AsMemory(0, encoded.Length - 1), recoverySecret, Scope()));
    }

    [Test]
    public void SeparateExportsUseFreshSaltAndNonce()
    {
        using SensitiveMaterialLease material = SensitiveMaterialLease.CreateCopy("value"u8);
        using SensitiveMaterialLease recoverySecret = PortableKeyRecovery.GenerateRecoverySecret();
        byte[] first = PortableKeyRecovery.Protect(material, recoverySecret, Scope());
        byte[] second = PortableKeyRecovery.Protect(material, recoverySecret, Scope());
        Assert.That(first.AsSpan(10, 44).SequenceEqual(second.AsSpan(10, 44)), Is.False);
        Assert.That(first, Is.Not.EqualTo(second));
    }

    [Test]
    public void RejectsShortRecoverySecretsAndUnboundScopes()
    {
        using SensitiveMaterialLease material = SensitiveMaterialLease.CreateCopy("value"u8);
        using SensitiveMaterialLease shortSecret = SensitiveMaterialLease.CreateCopy(new byte[16]);
        using SensitiveMaterialLease goodSecret = PortableKeyRecovery.GenerateRecoverySecret();

        Assert.Throws<ArgumentException>(() => PortableKeyRecovery.Protect(material, shortSecret, Scope()));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            PortableKeyRecovery.Protect(material, goodSecret, ReadOnlyMemory<byte>.Empty));
    }

    [Test]
    public void OversizedMaterialIsRejectedBeforeAllocatingAnEncryptedPackage()
    {
        using SensitiveMaterialLease material =
            SensitiveMaterialLease.CreateCopy(new byte[PortableKeyRecovery.MaximumMaterialLength + 1]);
        using SensitiveMaterialLease secret = PortableKeyRecovery.GenerateRecoverySecret();
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            PortableKeyRecovery.Protect(material, secret, Scope()));
    }
}
