using Laveyana.Security.Abstractions.Identifiers;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>
/// Tests exact persistent references and irreversible version identity representation.
/// </summary>
[TestFixture]
internal sealed class ReferenceTests
{
    private const string Provider = "11111111-1111-4111-8111-111111111111";
    private const string Key = "22222222-2222-4222-8222-222222222222";
    private const string Secret = "33333333-3333-4333-8333-333333333333";

    /// <summary>
    /// Checks strict identity round trips and explicit concatenation order.
    /// </summary>
    [Test]
    public void ReferencesHaveCanonicalStableText()
    {
        KeyReference keyReference = new(ProviderId.Parse(Provider), KeyId.Parse(Key), new KeyVersion(42));
        SecretReference secretReference = new(ProviderId.Parse(Provider), SecretId.Parse(Secret));

        Assert.Multiple(() =>
        {
            Assert.That(keyReference.ToString(), Is.EqualTo($"{Provider}/{Key}/42"));
            Assert.That(secretReference.ToString(), Is.EqualTo($"{Provider}/{Secret}"));
            Assert.That(KeyReference.Parse(keyReference.ToString()), Is.EqualTo(keyReference));
            Assert.That(SecretReference.Parse(secretReference.ToString()), Is.EqualTo(secretReference));
            Assert.That(new HashSet<KeyReference> { keyReference }.Contains(KeyReference.Parse(keyReference.ToString())), Is.True);
        });
    }

    /// <summary>
    /// Ensures neither key nor secret references can contain runtime aliases.
    /// </summary>
    [TestCase("primary/22222222-2222-4222-8222-222222222222/1")]
    [TestCase("11111111-1111-4111-8111-111111111111/master/1")]
    [TestCase("11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222/01")]
    [TestCase("11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222/0")]
    [TestCase("11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222/-1")]
    [TestCase("11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222/1/extra")]
    [TestCase("")]
    public void MalformedKeyReferencesAreRejected(string value)
    {
        Assert.That(KeyReference.TryParse(value, out _), Is.False);
    }

    /// <summary>
    /// Checks malformed provider aliases and wrong segment counts for secret references.
    /// </summary>
    [TestCase("primary/33333333-3333-4333-8333-333333333333")]
    [TestCase("11111111-1111-4111-8111-111111111111/33333333-3333-4333-8333-333333333333/1")]
    [TestCase("11111111-1111-4111-8111-111111111111/")]
    [TestCase("")]
    public void MalformedSecretReferencesAreRejected(string value)
    {
        Assert.That(SecretReference.TryParse(value, out _), Is.False);
    }

    /// <summary>
    /// Ensures a reference cannot be constructed with uninitialized components.
    /// </summary>
    [Test]
    public void UndefinedReferenceComponentsAreRejected()
    {
        ProviderId provider = ProviderId.Parse(Provider);
        KeyId key = KeyId.Parse(Key);
        SecretId secret = SecretId.Parse(Secret);

        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentException>(() => new KeyReference(default, key, new KeyVersion(1)));
            Assert.Throws<ArgumentException>(() => new KeyReference(provider, default, new KeyVersion(1)));
            Assert.Throws<ArgumentException>(() => new KeyReference(provider, key, default));
            Assert.Throws<ArgumentException>(() => new SecretReference(default, secret));
            Assert.Throws<ArgumentException>(() => new SecretReference(provider, default));
        });
    }

    /// <summary>
    /// Tests that versions are positive, canonical, and ordered within a key.
    /// </summary>
    [Test]
    public void KeyVersionIsPositiveCanonicalAndComparable()
    {
        Assert.Multiple(() =>
        {
            Assert.That(new KeyVersion(7).CompareTo(new KeyVersion(8)), Is.LessThan(0));
            Assert.That(KeyVersion.Parse(long.MaxValue.ToString(System.Globalization.CultureInfo.InvariantCulture)), Is.EqualTo(new KeyVersion(long.MaxValue)));
            Assert.That(KeyVersion.TryParse("01", out _), Is.False);
            Assert.That(KeyVersion.TryParse("+1", out _), Is.False);
            Assert.That(KeyVersion.TryParse("1.0", out _), Is.False);
            Assert.That(KeyVersion.TryParse("9223372036854775808", out _), Is.False);
            Assert.Throws<ArgumentOutOfRangeException>(() => new KeyVersion(0));
            Assert.Throws<ArgumentOutOfRangeException>(() => new KeyVersion(-1));
        });
    }
}
