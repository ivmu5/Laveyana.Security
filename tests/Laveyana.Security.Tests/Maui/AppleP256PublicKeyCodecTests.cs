using System.Security.Cryptography;
using Laveyana.Security.Maui.NativeKeys;
using NUnit.Framework;

namespace Laveyana.Security.Tests.Maui;

[TestFixture]
public sealed class AppleP256PublicKeyCodecTests
{
    [Test]
    public void ValidP256PointRoundTripsAsSpki()
    {
        using ECDsa source = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters point = source.ExportParameters(false);
        byte[] x963 = new byte[65];
        x963[0] = 0x04;
        point.Q.X!.CopyTo(x963, 1);
        point.Q.Y!.CopyTo(x963, 33);

        byte[] spki = AppleP256PublicKeyCodec.ToSubjectPublicKeyInfo(x963);
        Assert.That(spki, Is.EqualTo(source.ExportSubjectPublicKeyInfo()));

        byte[] message = "apple-secure-enclave-public"u8.ToArray();
        byte[] signature = source.SignData(message, HashAlgorithmName.SHA256);
        using ECDsa imported = ECDsa.Create();
        imported.ImportSubjectPublicKeyInfo(spki, out int read);
        Assert.That(read, Is.EqualTo(spki.Length));
        Assert.That(imported.VerifyData(message, signature, HashAlgorithmName.SHA256), Is.True);
    }

    [Test]
    public void RejectsMalformedPointLengthsAndPrefix()
    {
        Assert.Throws<CryptographicException>(() => AppleP256PublicKeyCodec.ToSubjectPublicKeyInfo([]));
        Assert.Throws<CryptographicException>(() => AppleP256PublicKeyCodec.ToSubjectPublicKeyInfo(new byte[64]));
        Assert.Throws<CryptographicException>(() => AppleP256PublicKeyCodec.ToSubjectPublicKeyInfo(new byte[66]));
        byte[] malformed = new byte[65];
        Assert.Throws<CryptographicException>(() => AppleP256PublicKeyCodec.ToSubjectPublicKeyInfo(malformed));
    }

    [Test]
    public void RejectsPointNotOnP256Curve()
    {
        byte[] invalid = new byte[65];
        invalid[0] = 0x04;
        Assert.Catch<CryptographicException>(() => AppleP256PublicKeyCodec.ToSubjectPublicKeyInfo(invalid));
    }
}
