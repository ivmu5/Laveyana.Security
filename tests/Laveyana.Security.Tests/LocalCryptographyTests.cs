using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Algorithms;
using Laveyana.Security.Primitives;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Validates Generation 1 primitives against externally published test vectors.</summary>
[TestFixture]
internal sealed class LocalCryptographyTests
{
    [Test]
    public void Sha256MatchesNistAbcVector()
    {
        byte[] actual = LocalCryptography.Sha256("abc"u8);
        Assert.That(Convert.ToHexStringLower(actual),
            Is.EqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    }

    [TestCase("sha-384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")]
    [TestCase("sha-512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")]
    public void SupportedHashesMatchStandardAbcVectors(string token, string digest)
    {
        byte[] output = new byte[digest.Length / 2];
        int written = AdvancedLocalPrimitives.Hash(new AlgorithmId(token), "abc"u8, output);
        Assert.Multiple(() =>
        {
            Assert.That(written, Is.EqualTo(output.Length));
            Assert.That(Convert.ToHexStringLower(output), Is.EqualTo(digest));
        });
    }

    [TestCase("hmac-sha-256", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")]
    [TestCase("hmac-sha-384", "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")]
    [TestCase("hmac-sha-512", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")]
    public void HmacMatchesRfc4231Case1(string token, string expected)
    {
        AlgorithmId algorithm = new(token);
        byte[] key = Enumerable.Repeat((byte)0x0b, 20).ToArray();
        byte[] output = new byte[expected.Length / 2];
        int written = AdvancedLocalPrimitives.Hmac(algorithm, key, "Hi There"u8, output);
        Assert.Multiple(() =>
        {
            Assert.That(written, Is.EqualTo(output.Length));
            Assert.That(Convert.ToHexStringLower(output), Is.EqualTo(expected));
            Assert.That(AdvancedLocalPrimitives.VerifyHmac(algorithm, key, "Hi There"u8, output), Is.True);
        });

        output[0] ^= 1;
        Assert.That(AdvancedLocalPrimitives.VerifyHmac(algorithm, key, "Hi There"u8, output), Is.False);
        Assert.That(AdvancedLocalPrimitives.VerifyHmac(algorithm, key, "Hi There"u8, output.AsSpan(0, 3)), Is.False);
    }

    [Test]
    public void HkdfMatchesRfc5869Case1()
    {
        byte[] input = Enumerable.Repeat((byte)0x0b, 22).ToArray();
        byte[] salt = Convert.FromHexString("000102030405060708090a0b0c");
        byte[] info = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9");
        byte[] output = new byte[42];
        AdvancedLocalPrimitives.HkdfSha256(input, salt, info, output);
        Assert.That(Convert.ToHexStringLower(output), Is.EqualTo(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    }

    [TestCase(1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")]
    [TestCase(2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")]
    public void HistoricalPbkdf2Sha256MatchesKnownVectors(int iterations, string expected)
    {
        byte[] result = new byte[32];
        AdvancedLocalPrimitives.DeriveHistoricalPbkdf2Sha256("password"u8, "salt"u8, iterations, result);
        Assert.That(Convert.ToHexStringLower(result), Is.EqualTo(expected));
    }

    [Test]
    public void LegacyHmacSha1MatchesRfc2202AndRequiresHistoricalUsage()
    {
        byte[] key = Enumerable.Repeat((byte)0x0b, 20).ToArray();
        byte[] output = new byte[20];
        int written = AdvancedLocalPrimitives.Hmac(
            WellKnownAlgorithms.HmacSha1, key, "Hi There"u8, output, AlgorithmUse.HistoricalVerification);
        Assert.That(written, Is.EqualTo(20));
        Assert.That(Convert.ToHexStringLower(output), Is.EqualTo("b617318655057264e28bc0b6fb378c8ef146be00"));
        Assert.That(AdvancedLocalPrimitives.VerifyHmac(
            WellKnownAlgorithms.HmacSha1, key, "Hi There"u8, output, AlgorithmUse.HistoricalVerification), Is.True);
    }

    [Test]
    public void RandomGenerationAndFixedTimeComparisonHaveExpectedSemantics()
    {
        byte[] left = LocalCryptography.GenerateRandomBytes(32);
        byte[] right = LocalCryptography.GenerateRandomBytes(32);
        Assert.Multiple(() =>
        {
            Assert.That(left, Has.Length.EqualTo(32));
            Assert.That(right, Has.Length.EqualTo(32));
            Assert.That(LocalCryptography.FixedTimeEquals(left, left), Is.True);
            Assert.That(LocalCryptography.FixedTimeEquals(left, right), Is.False);
            Assert.That(LocalCryptography.FixedTimeEquals(left, right[..8]), Is.False);
        });

        Span<byte> destination = stackalloc byte[32];
        LocalCryptography.FillRandom(destination);
        Assert.That(destination.ToArray(), Has.Length.EqualTo(32));
        CryptographicOperations.ZeroMemory(destination);
    }

    [Test]
    public void SafeDefaultsRejectShortHmacKeysAndAllowFullLengthAuthentication()
    {
        byte[] key = new byte[32];
        LocalCryptography.FillRandom(key);
        byte[] mac = LocalCryptography.HmacSha256(key, "payload"u8);
        Assert.That(LocalCryptography.VerifyHmacSha256(key, "payload"u8, mac), Is.True);
        Assert.That(LocalCryptography.VerifyHmacSha256(key, "different"u8, mac), Is.False);
        Assert.Throws<ArgumentException>(() => LocalCryptography.HmacSha256(new byte[8], "payload"u8));
        CryptographicOperations.ZeroMemory(key);
    }

    [Test]
    public void SafeDefaultHkdfRequiresSaltAndDomainSeparation()
    {
        byte[] ikm = new byte[32];
        byte[] salt = new byte[16];
        byte[] derived = new byte[32];
        LocalCryptography.FillRandom(ikm);
        LocalCryptography.FillRandom(salt);
        LocalCryptography.DeriveHkdfSha256(ikm, salt, "protocol/key-v1"u8, derived);
        Assert.That(derived, Has.Length.EqualTo(32));
        Assert.Throws<ArgumentException>(() => LocalCryptography.DeriveHkdfSha256(
            new byte[32], new byte[4], "context"u8, new byte[32]));
        Assert.Throws<ArgumentException>(() => LocalCryptography.DeriveHkdfSha256(
            new byte[32], new byte[16], ReadOnlySpan<byte>.Empty, new byte[32]));
        CryptographicOperations.ZeroMemory(derived);
        CryptographicOperations.ZeroMemory(ikm);
    }

    [Test]
    public void Pbkdf2ExplicitPolicyValidationRejectsWeakenedNewValues()
    {
        Assert.Multiple(() =>
        {
            Assert.That(Pbkdf2WorkFactor.Generation1Default.PolicyVersion, Is.EqualTo(1));
            Assert.That(Pbkdf2WorkFactor.Generation1Default.Iterations, Is.EqualTo(600_000));
        });
        Assert.Throws<ArgumentOutOfRangeException>(() => new Pbkdf2WorkFactor(0, 600_000));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Pbkdf2WorkFactor(1, 1_000));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Pbkdf2WorkFactor(1, 10_000_001));
        Assert.Throws<ArgumentException>(() => LocalCryptography.DerivePbkdf2Sha256(
            "password"u8, new byte[16], default, new byte[32]));
        Assert.Throws<ArgumentException>(() => LocalCryptography.DerivePbkdf2Sha256(
            "password"u8, new byte[8], Pbkdf2WorkFactor.Generation1Default, new byte[32]));
        Assert.Throws<ArgumentOutOfRangeException>(() => LocalCryptography.GenerateRandomBytes(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => LocalCryptography.GenerateRandomBytes(1_048_577));
        Assert.Throws<ArgumentOutOfRangeException>(() => AdvancedLocalPrimitives.DeriveHistoricalPbkdf2Sha256(
            "password"u8, "salt"u8, 0, new byte[32]));
        Assert.Throws<ArgumentOutOfRangeException>(() => AdvancedLocalPrimitives.HkdfSha256(
            "input"u8, new byte[0], new byte[0], new byte[8161]));
        Assert.Throws<ArgumentOutOfRangeException>(() => AdvancedLocalPrimitives.DeriveHistoricalPbkdf2Sha256(
            "password"u8, "salt"u8, 10_000_001, new byte[32]));
        Assert.Throws<ArgumentException>(() => LocalCryptography.DerivePbkdf2Sha256(
            ReadOnlySpan<byte>.Empty, new byte[16], Pbkdf2WorkFactor.Generation1Default, new byte[32]));
    }

    [Test]
    public void Generation1Pbkdf2WorksWithMinimumConfiguredCost()
    {
        byte[] salt = "0123456789abcdef"u8.ToArray();
        byte[] output = new byte[32];
        LocalCryptography.DerivePbkdf2Sha256("test-password"u8, salt, Pbkdf2WorkFactor.Generation1Default, output);
        Assert.That(Convert.ToHexStringLower(output), Is.EqualTo(
            "61535339ab372ad8fd071a34a3b4e06c35aa5523fa88ed58a4d52b4034068e00"));
        CryptographicOperations.ZeroMemory(output);
    }
}
