using System.Security.Cryptography;
using Laveyana.Security.Maui.NativeKeys;
using NUnit.Framework;

namespace Laveyana.Security.Tests.Maui;

[TestFixture]
public sealed class EcdsaDerSignatureCodecTests
{
    [Test]
    public void ConvertsAndroidStyleDerSignatureToVerifiableP1363()
    {
        using ECDsa signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] message = "cross-platform-signature"u8.ToArray();
        byte[] der = signer.SignData(message, HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);

        byte[] p1363 = EcdsaDerSignatureCodec.ToP1363(der);
        Assert.That(p1363, Has.Length.EqualTo(64));
        Assert.That(signer.VerifyData(message, p1363, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation), Is.True);
    }

    [TestCaseSource(nameof(MalformedDer))]
    public void RejectsMalformedDer(byte[] data)
    {
        Assert.Throws<CryptographicException>(() => EcdsaDerSignatureCodec.ToP1363(data));
    }

    private static IEnumerable<byte[]> MalformedDer()
    {
        yield return [];
        yield return [0x30, 0x00];
        yield return [0x30, 0x06, 0x02, 0x01, 0xff, 0x02, 0x01, 0x01];
        yield return [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0xff];
        yield return [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00];
        yield return [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];
    }
}
