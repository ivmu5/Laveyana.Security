using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Algorithms;
using Laveyana.Security.Primitives;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Protects fail-closed algorithm selection and purpose separation.</summary>
[TestFixture]
internal sealed class AlgorithmPolicyTests
{
    [Test]
    public void CatalogContainsExpectedDefaultAndAlternatives()
    {
        Assert.Multiple(() =>
        {
            Assert.That(AlgorithmPolicy.Get(WellKnownAlgorithms.Sha256).Status, Is.EqualTo(AlgorithmStatus.Recommended));
            Assert.That(AlgorithmPolicy.Get(WellKnownAlgorithms.Sha384).Status, Is.EqualTo(AlgorithmStatus.Supported));
            Assert.That(AlgorithmPolicy.Get(WellKnownAlgorithms.HmacSha1).Status, Is.EqualTo(AlgorithmStatus.LegacyReadOnly));
            Assert.That(AlgorithmPolicy.Get(WellKnownAlgorithms.HkdfSha256).Purpose, Is.EqualTo(AlgorithmPurpose.GeneralKdf));
            Assert.That(AlgorithmPolicy.Get(WellKnownAlgorithms.Aes256Gcm).RequiresPlatformSupport, Is.True);
            Assert.That(AlgorithmPolicy.Get(WellKnownAlgorithms.ChaCha20Poly1305).RequiresPlatformSupport, Is.True);
            Assert.That(AlgorithmPolicy.All.Select(static d => d.Id).Distinct().Count(), Is.EqualTo(AlgorithmPolicy.All.Count));
        });
    }

    [Test]
    public void UnknownAndUndefinedAlgorithmsAreRejectedWithoutFallback()
    {
        Assert.Throws<CryptographicException>(() => AlgorithmPolicy.Get(default));
        Assert.Throws<CryptographicException>(() => AlgorithmPolicy.EnsureAllowed(
            new AlgorithmId("sha-999"), AlgorithmPurpose.Hash, AlgorithmUse.NewOperation));
        Assert.Throws<CryptographicException>(() => AlgorithmPolicy.EnsureAllowed(
            WellKnownAlgorithms.HmacSha256, AlgorithmPurpose.Hash, AlgorithmUse.NewOperation));
    }

    [Test]
    public void LegacyAlgorithmsCannotProduceNewValues()
    {
        Assert.Throws<CryptographicException>(() => AlgorithmPolicy.EnsureAllowed(
            WellKnownAlgorithms.Sha1, AlgorithmPurpose.Hash, AlgorithmUse.NewOperation));
        Assert.Throws<CryptographicException>(() => AlgorithmPolicy.EnsureAllowed(
            WellKnownAlgorithms.HmacSha1, AlgorithmPurpose.Mac, AlgorithmUse.NewOperation));
        Assert.DoesNotThrow(() => AlgorithmPolicy.EnsureAllowed(
            WellKnownAlgorithms.HmacSha1, AlgorithmPurpose.Mac, AlgorithmUse.HistoricalVerification));
        Assert.Throws<CryptographicException>(() => AdvancedLocalPrimitives.Hash(
            WellKnownAlgorithms.Sha1, new byte[1], new byte[20]));
        Assert.Throws<CryptographicException>(() => AdvancedLocalPrimitives.Hmac(
            WellKnownAlgorithms.HmacSha1, new byte[20], new byte[1], new byte[20]));
    }

    [Test]
    public void InvalidUsageEnumsAreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => AlgorithmPolicy.EnsureAllowed(
            WellKnownAlgorithms.Sha256, (AlgorithmPurpose)int.MaxValue, AlgorithmUse.NewOperation));
        Assert.Throws<ArgumentOutOfRangeException>(() => AlgorithmPolicy.EnsureAllowed(
            WellKnownAlgorithms.Sha256, AlgorithmPurpose.Hash, (AlgorithmUse)int.MaxValue));
    }

    [Test]
    public void AeadAvailabilityIsCheckedAndNeverSubstituted()
    {
        Assert.That(AlgorithmPolicy.IsPlatformSupported(WellKnownAlgorithms.Aes256Gcm),
            Is.EqualTo(AesGcm.IsSupported));
        Assert.That(AlgorithmPolicy.IsPlatformSupported(WellKnownAlgorithms.ChaCha20Poly1305),
            Is.EqualTo(ChaCha20Poly1305.IsSupported));
        if (!ChaCha20Poly1305.IsSupported)
        {
            Assert.Throws<PlatformNotSupportedException>(() => AlgorithmPolicy.EnsureAllowed(
                WellKnownAlgorithms.ChaCha20Poly1305, AlgorithmPurpose.AuthenticatedEncryption, AlgorithmUse.NewOperation));
        }
    }
}
