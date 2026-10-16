using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Payloads;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Phase 15 framing, immutable ownership and cross-boundary AEAD metadata tests.</summary>
[TestFixture]
internal sealed class ManagedPayloadTests
{
    private static readonly KeyReference Reference = new(
        ProviderId.Parse("11111111-1111-4111-8111-111111111111"),
        KeyId.Parse("22222222-2222-4222-8222-222222222222"), new KeyVersion(7));

    private static readonly KeyReference DifferentVersion = new(
        ProviderId.Parse("11111111-1111-4111-8111-111111111111"),
        KeyId.Parse("22222222-2222-4222-8222-222222222222"), new KeyVersion(8));

    private static readonly byte[] Nonce = Enumerable.Range(0, 12).Select(x => (byte)x).ToArray();
    private static readonly byte[] Tag = Enumerable.Range(160, 16).Select(x => (byte)x).ToArray();

    private static byte[] Fixture(string name) => Convert.FromHexString(
        File.ReadAllText(Path.Combine(TestContext.CurrentContext.TestDirectory, "Fixtures", name)).Trim());

    private static EncryptedPayload Sample() => new(Reference, WellKnownAlgorithms.Aes256Gcm, Nonce,
        [0, 170, 187], Tag);

    [Test]
    public void GoldenEncryptedAndDetachedRecordsAreStable()
    {
        EncryptedPayload payload = Sample();
        Assert.That(ManagedPayloadCodec.Encode(payload), Is.EqualTo(Fixture("encrypted-payload-v1.hex")));
        EncryptedPayload decoded = ManagedPayloadCodec.DecodeEncrypted(Fixture("encrypted-payload-v1.hex"));
        Assert.That(decoded.Reference, Is.EqualTo(Reference));
        Assert.That(decoded.Algorithm, Is.EqualTo(WellKnownAlgorithms.Aes256Gcm));
        Assert.That(decoded.CiphertextLength, Is.EqualTo(3));
        Assert.That(decoded.ExportCiphertextCopy(), Is.EqualTo(new byte[] { 0, 170, 187 }));

        DetachedEncryptedPayload detached = payload.Detach(out byte[] ciphertext);
        Assert.That(ManagedPayloadCodec.Encode(detached), Is.EqualTo(Fixture("detached-payload-v1.hex")));
        DetachedEncryptedPayload restored = ManagedPayloadCodec.DecodeDetached(Fixture("detached-payload-v1.hex"));
        Assert.That(ManagedPayloadCodec.Encode(restored.Attach(ciphertext)), Is.EqualTo(ManagedPayloadCodec.Encode(payload)));
        Assert.Throws<ArgumentException>(() => restored.Attach([1, 2]));
    }

    [Test]
    public void GoldenSignatureAndMacRecordsAreStable()
    {
        SignaturePayload signature = new(Reference, WellKnownAlgorithms.EcdsaP256Sha256,
            Enumerable.Range(0, 64).Select(x => (byte)x).ToArray());
        MacResult mac = new(Reference, WellKnownAlgorithms.HmacSha256,
            Enumerable.Range(0, 32).Select(x => (byte)x).ToArray());
        Assert.That(signature.Encoding, Is.EqualTo("ieee-p1363"));
        Assert.That(ManagedPayloadCodec.Encode(signature), Is.EqualTo(Fixture("signature-payload-v1.hex")));
        Assert.That(ManagedPayloadCodec.Encode(mac), Is.EqualTo(Fixture("mac-result-v1.hex")));
        Assert.That(ManagedPayloadCodec.DecodeSignature(ManagedPayloadCodec.Encode(signature)).Reference,
            Is.EqualTo(Reference));
        Assert.That(ManagedPayloadCodec.DecodeMac(ManagedPayloadCodec.Encode(mac)).ExportTagCopy(),
            Is.EqualTo(mac.ExportTagCopy()));
    }

    [Test]
    public void AllResultTypesDefensivelyCopyInputAndOutput()
    {
        byte[] nonce = (byte[])Nonce.Clone();
        byte[] tag = (byte[])Tag.Clone();
        byte[] ciphertext = [5, 4, 3];
        EncryptedPayload encrypted = new(Reference, WellKnownAlgorithms.Aes256Gcm, nonce, ciphertext, tag);
        nonce[0] = 255;
        tag[0] = 255;
        ciphertext[0] = 255;
        encrypted.ExportNonceCopy()[0] = 255;
        encrypted.ExportAuthenticationTagCopy()[0] = 255;
        encrypted.ExportCiphertextCopy()[0] = 255;
        Assert.That(encrypted.ExportNonceCopy()[0], Is.Zero);
        Assert.That(encrypted.ExportAuthenticationTagCopy()[0], Is.EqualTo(160));
        Assert.That(encrypted.ExportCiphertextCopy()[0], Is.EqualTo(5));

        byte[] signatureBytes = Enumerable.Range(0, 64).Select(x => (byte)x).ToArray();
        SignaturePayload signature = new(Reference, WellKnownAlgorithms.EcdsaP256Sha256, signatureBytes);
        signatureBytes[0] = 255;
        signature.ExportSignatureCopy()[0] = 255;
        Assert.That(signature.ExportSignatureCopy()[0], Is.Zero);

        byte[] macBytes = new byte[32];
        MacResult mac = new(Reference, WellKnownAlgorithms.HmacSha256, macBytes);
        macBytes[0] = 255;
        mac.ExportTagCopy()[0] = 255;
        Assert.That(mac.ExportTagCopy()[0], Is.Zero);
    }

    [Test]
    public void ConstructorsRejectUninitializedIdentityAndUnsupportedRepresentations()
    {
        Assert.Throws<ArgumentException>(() => new EncryptedPayload(default, WellKnownAlgorithms.Aes256Gcm, Nonce, [], Tag));
        Assert.Throws<ArgumentException>(() => new EncryptedPayload(Reference, WellKnownAlgorithms.Sha256, Nonce, [], Tag));
        Assert.Throws<ArgumentException>(() => new EncryptedPayload(Reference, WellKnownAlgorithms.Aes256Gcm, [1], [], Tag));
        Assert.Throws<ArgumentException>(() => new EncryptedPayload(Reference, WellKnownAlgorithms.Aes256Gcm, Nonce, [], [1]));
        Assert.Throws<ArgumentException>(() => new SignaturePayload(Reference, WellKnownAlgorithms.Sha256, new byte[64]));
        Assert.Throws<ArgumentException>(() => new SignaturePayload(Reference, WellKnownAlgorithms.EcdsaP256Sha256, new byte[65]));
        Assert.Throws<ArgumentException>(() => new MacResult(Reference, WellKnownAlgorithms.HmacSha1, new byte[20]));
        Assert.Throws<ArgumentException>(() => new MacResult(Reference, WellKnownAlgorithms.HmacSha256, new byte[16]));
        Assert.Throws<ArgumentException>(() => new DetachedEncryptedPayload(Reference, WellKnownAlgorithms.Aes256Gcm, Nonce, Tag, -1));
    }

    [Test]
    public void MalformedMarkersVersionsFlagsAndTrailingBytesAreRejected()
    {
        byte[] original = Fixture("encrypted-payload-v1.hex");
        byte[] marker = (byte[])original.Clone();
        marker[0] ^= 1;
        Assert.Throws<InvalidDataException>(() => ManagedPayloadCodec.DecodeEncrypted(marker));
        byte[] futureVersion = (byte[])original.Clone();
        futureVersion[4] = 2;
        Assert.Throws<NotSupportedException>(() => ManagedPayloadCodec.DecodeEncrypted(futureVersion));
        byte[] flags = (byte[])original.Clone();
        flags[6] = 1;
        Assert.Throws<InvalidDataException>(() => ManagedPayloadCodec.DecodeEncrypted(flags));
        Assert.Throws<InvalidDataException>(() => ManagedPayloadCodec.DecodeEncrypted([.. original, 0]));
        Assert.Throws<InvalidDataException>(() => ManagedPayloadCodec.DecodeEncrypted(original[..^1]));
        Assert.Throws<InvalidDataException>(() => ManagedPayloadCodec.DecodeDetached(original));
    }

    [Test]
    public void ExcessiveLengthsMalformedUtf8AndInconsistentMacSizeFailClosed()
    {
        byte[] encrypted = Fixture("encrypted-payload-v1.hex");
        byte[] oversized = (byte[])encrypted.Clone();
        // Last field begins with a UInt32 length before its three ciphertext bytes.
        oversized[^7] = 0xFF;
        oversized[^6] = 0xFF;
        oversized[^5] = 0xFF;
        oversized[^4] = 0x7F;
        Assert.Throws<InvalidDataException>(() => ManagedPayloadCodec.DecodeEncrypted(oversized));

        byte[] badUtf8 = (byte[])encrypted.Clone();
        int start = FindBytes(badUtf8, "11111111-1111-4111-8111-111111111111"u8.ToArray());
        Assert.That(start, Is.GreaterThanOrEqualTo(0));
        badUtf8[start] = 0xFF;
        Assert.Catch<Exception>(() => ManagedPayloadCodec.DecodeEncrypted(badUtf8));

        byte[] mac = Fixture("mac-result-v1.hex");
        byte[] shortTag = mac[..^1];
        Assert.Throws<InvalidDataException>(() => ManagedPayloadCodec.DecodeMac(shortTag));
        Assert.Throws<InvalidDataException>(() => ManagedPayloadCodec.DecodeEncrypted(new byte[0]));
    }

    [Test]
    public void UnknownRecordVersionsFailClosedAcrossAllFourFormats()
    {
        byte[][] frames =
        [
            Fixture("encrypted-payload-v1.hex"),
            Fixture("detached-payload-v1.hex"),
            Fixture("signature-payload-v1.hex"),
            Fixture("mac-result-v1.hex")
        ];
        foreach (byte[] frame in frames)
        {
            frame[4] = 2;
        }

        Assert.Throws<NotSupportedException>(() => ManagedPayloadCodec.DecodeEncrypted(frames[0]));
        Assert.Throws<NotSupportedException>(() => ManagedPayloadCodec.DecodeDetached(frames[1]));
        Assert.Throws<NotSupportedException>(() => ManagedPayloadCodec.DecodeSignature(frames[2]));
        Assert.Throws<NotSupportedException>(() => ManagedPayloadCodec.DecodeMac(frames[3]));
    }

    [Test]
    public void WrongExactReferenceAndUnknownSignatureEncodingAreRejected()
    {
        byte[] wrongVersion = Fixture("encrypted-payload-v1.hex");
        int offset = FindBytes(wrongVersion, "11111111-1111-4111-8111-111111111111"u8.ToArray());
        Assert.That(offset, Is.GreaterThanOrEqualTo(0));
        wrongVersion[offset] = (byte)'Z';
        Assert.Throws<InvalidDataException>(() => ManagedPayloadCodec.DecodeEncrypted(wrongVersion));

        byte[] signature = Fixture("signature-payload-v1.hex");
        int encOffset = FindBytes(signature, "ieee-p1363"u8.ToArray());
        Assert.That(encOffset, Is.GreaterThanOrEqualTo(0));
        signature[encOffset] = (byte)'x';
        Assert.Throws<InvalidDataException>(() => ManagedPayloadCodec.DecodeSignature(signature));
    }

    [Test]
    public void CodecFuzzNeverAcceptsRandomFramesAsValidResults()
    {
        Random rng = new(20261009);
        for (int i = 0; i < 300; i++)
        {
            byte[] noise = new byte[rng.Next(0, 800)];
            rng.NextBytes(noise);
            Assert.Catch<Exception>(() => ManagedPayloadCodec.DecodeEncrypted(noise));
            Assert.Catch<Exception>(() => ManagedPayloadCodec.DecodeDetached(noise));
            Assert.Catch<Exception>(() => ManagedPayloadCodec.DecodeSignature(noise));
            Assert.Catch<Exception>(() => ManagedPayloadCodec.DecodeMac(noise));
        }
    }

    [Test]
    public void AuthenticatedMetadataBindsKeyAlgorithmNonceLengthAndApplicationAad()
    {
        byte[] key = Enumerable.Range(0, 32).Select(x => (byte)x).ToArray();
        byte[] input = "some confidential content"u8.ToArray();
        byte[] userAad = "account:42/v1"u8.ToArray();
        byte[] ciphertext = new byte[input.Length];
        byte[] tag = new byte[16];
        byte[] aad = EncryptedPayloadAssociatedData.Build(Reference, WellKnownAlgorithms.Aes256Gcm,
            Nonce, input.Length, userAad);
        using AesGcm aes = new(key, 16);
        aes.Encrypt(Nonce, input, ciphertext, tag, aad);
        EncryptedPayload result = new(Reference, WellKnownAlgorithms.Aes256Gcm, Nonce, ciphertext, tag);
        byte[] encoded = ManagedPayloadCodec.Encode(result);
        EncryptedPayload loaded = ManagedPayloadCodec.DecodeEncrypted(encoded);
        byte[] plaintext = new byte[input.Length];
        aes.Decrypt(loaded.ExportNonceCopy(), loaded.ExportCiphertextCopy(),
            loaded.ExportAuthenticationTagCopy(), plaintext, loaded.BuildAssociatedData(userAad));
        Assert.That(plaintext, Is.EqualTo(input));
        Assert.That(result.BuildAssociatedData(userAad), Is.EqualTo(loaded.BuildAssociatedData(userAad)));

        Assert.Catch<CryptographicException>(() =>
            aes.Decrypt(Nonce, ciphertext, tag, new byte[input.Length], result.BuildAssociatedData("account:43/v1"u8)));

        EncryptedPayload wrongVersion = new(DifferentVersion, WellKnownAlgorithms.Aes256Gcm, Nonce, ciphertext, tag);
        Assert.Catch<CryptographicException>(() =>
            aes.Decrypt(Nonce, ciphertext, tag, new byte[input.Length], wrongVersion.BuildAssociatedData(userAad)));

        byte[] wrongNonce = (byte[])Nonce.Clone();
        wrongNonce[0] ^= 1;
        EncryptedPayload replacedNonce = new(Reference, WellKnownAlgorithms.Aes256Gcm, wrongNonce, ciphertext, tag);
        Assert.Catch<CryptographicException>(() =>
            aes.Decrypt(wrongNonce, ciphertext, tag, new byte[input.Length], replacedNonce.BuildAssociatedData(userAad)));

        byte[] tamperedCiphertext = (byte[])ciphertext.Clone();
        tamperedCiphertext[0] ^= 1;
        Assert.Catch<CryptographicException>(() =>
            aes.Decrypt(Nonce, tamperedCiphertext, tag, new byte[input.Length], loaded.BuildAssociatedData(userAad)));
    }

    [Test]
    public void ExternalAadIsNotEmbeddedInEncodedResult()
    {
        EncryptedPayload payload = Sample();
        byte[] external = Enumerable.Repeat((byte)0xFE, 64).ToArray();
        byte[] encoded = ManagedPayloadCodec.Encode(payload);
        Assert.That(FindBytes(encoded, external), Is.EqualTo(-1));
        Assert.That(payload.BuildAssociatedData(external), Is.Not.EqualTo(payload.BuildAssociatedData()));
        Assert.Throws<ArgumentOutOfRangeException>(() => payload.BuildAssociatedData(new byte[65537]));
    }

    [Test]
    public void DetachedAadUsesCommittedFullCiphertextLength()
    {
        EncryptedPayload encrypted = Sample();
        DetachedEncryptedPayload detached = encrypted.Detach(out byte[] bytes);
        Assert.That(detached.BuildAssociatedData(), Is.EqualTo(encrypted.BuildAssociatedData()));
        Assert.That(detached.Attach(bytes).BuildAssociatedData(), Is.EqualTo(encrypted.BuildAssociatedData()));
        DetachedEncryptedPayload wrongLength = new(Reference, WellKnownAlgorithms.Aes256Gcm, Nonce, Tag, 2);
        Assert.That(wrongLength.BuildAssociatedData(), Is.Not.EqualTo(detached.BuildAssociatedData()));
    }

    [Test]
    public void BinaryPayloadsDoNotIncludeApplicationAadOrSensitiveMaterialInToString()
    {
        EncryptedPayload encrypted = Sample();
        SignaturePayload signature = new(Reference, WellKnownAlgorithms.EcdsaP256Sha256, new byte[64]);
        MacResult mac = new(Reference, WellKnownAlgorithms.HmacSha256, new byte[32]);
        Assert.That(encrypted.ToString(), Does.Contain("UNVERIFIED"));
        Assert.That(signature.ToString(), Does.Contain("UNVERIFIED"));
        Assert.That(mac.ToString(), Does.Contain("UNVERIFIED"));
    }

    private static int FindBytes(byte[] haystack, byte[] needle) => haystack.AsSpan().IndexOf(needle);
}
