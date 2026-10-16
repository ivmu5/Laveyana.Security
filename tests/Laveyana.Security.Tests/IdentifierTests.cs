using System.Globalization;
using Laveyana.Security.Abstractions.Identifiers;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>
/// Protects stable, strongly typed cryptographic identities and parsing rules.
/// </summary>
[TestFixture]
internal sealed class IdentifierTests
{
    private const string Canonical = "12345678-1234-4234-8234-123456789abc";
    private const string Other = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    /// <summary>
    /// Checks canonical, culture-independent round trips for every UUID identity.
    /// </summary>
    [Test]
    public void UuidIdentitiesRoundTripWithoutClrTypeNames()
    {
        ProviderId provider = ProviderId.Parse(Canonical);
        KeyId key = KeyId.Parse(Canonical);
        SecretId secret = SecretId.Parse(Canonical);

        Assert.Multiple(() =>
        {
            Assert.That(provider.ToString(), Is.EqualTo(Canonical));
            Assert.That(key.ToString(), Is.EqualTo(Canonical));
            Assert.That(secret.ToString(), Is.EqualTo(Canonical));
            Assert.That(ProviderId.Parse(provider.ToString()), Is.EqualTo(provider));
            Assert.That(KeyId.Parse(key.ToString()), Is.EqualTo(key));
            Assert.That(SecretId.Parse(secret.ToString()), Is.EqualTo(secret));
            Assert.That(provider.Value, Is.EqualTo(key.Value));
            Assert.That(provider.Value, Is.EqualTo(secret.Value));
        });
    }

    /// <summary>
    /// Rejects malformed, ambiguous and noncanonical UUID forms.
    /// </summary>
    [TestCase(null)]
    [TestCase("")]
    [TestCase("00000000-0000-0000-0000-000000000000")]
    [TestCase("12345678123442348234123456789abc")]
    [TestCase("12345678-1234-4234-8234-123456789ABC")]
    [TestCase("{12345678-1234-4234-8234-123456789abc}")]
    [TestCase(" 12345678-1234-4234-8234-123456789abc")]
    [TestCase("12345678-1234-4234-8234-123456789abc ")]
    [TestCase("runtime.ProviderId")]
    public void MalformedUuidIdentitiesAreRejected(string? text)
    {
        Assert.Multiple(() =>
        {
            Assert.That(ProviderId.TryParse(text, out _), Is.False);
            Assert.That(KeyId.TryParse(text, out _), Is.False);
            Assert.That(SecretId.TryParse(text, out _), Is.False);
        });
    }

    /// <summary>
    /// Ensures no default struct can masquerade as a defined identity.
    /// </summary>
    [Test]
    public void DefaultIdentityValuesAreNotDefined()
    {
        Assert.Multiple(() =>
        {
            Assert.That(default(ProviderId).IsDefined, Is.False);
            Assert.That(default(KeyId).IsDefined, Is.False);
            Assert.That(default(SecretId).IsDefined, Is.False);
            Assert.That(default(ProviderAlias).IsDefined, Is.False);
            Assert.That(default(KeyName).IsDefined, Is.False);
            Assert.That(default(AlgorithmId).IsDefined, Is.False);
            Assert.That(default(CapabilityId).IsDefined, Is.False);
            Assert.That(default(KeyVersion).IsDefined, Is.False);
            Assert.That(default(KeyReference).IsDefined, Is.False);
            Assert.That(default(SecretReference).IsDefined, Is.False);
        });
        Assert.Throws<ArgumentOutOfRangeException>(() => new ProviderId(Guid.Empty));
        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyId(Guid.Empty));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecretId(Guid.Empty));
    }

    /// <summary>
    /// Checks strong value equality, including hashed collections and provider scope.
    /// </summary>
    [Test]
    public void ValueEqualityAndHashingAreStableWithinProcess()
    {
        ProviderId first = ProviderId.Parse(Canonical);
        ProviderId same = ProviderId.Parse(Canonical);
        ProviderId second = ProviderId.Parse(Other);
        HashSet<ProviderId> providers = [first];

        Assert.Multiple(() =>
        {
            Assert.That(first, Is.EqualTo(same));
            Assert.That(first.GetHashCode(), Is.EqualTo(same.GetHashCode()));
            Assert.That(first, Is.Not.EqualTo(second));
            Assert.That(providers.Contains(same), Is.True);
            Assert.That(providers.Contains(second), Is.False);
            Assert.That(KeyId.Parse(Canonical), Is.EqualTo(KeyId.Parse(Canonical)));
            Assert.That(SecretId.Parse(Canonical), Is.EqualTo(SecretId.Parse(Canonical)));
        });
    }

    /// <summary>
    /// Validates exact-case aliases without silently applying culture-sensitive transforms.
    /// </summary>
    [Test]
    public void NamesAreOrdinalAndPreserveTheOriginalText()
    {
        ProviderAlias upperAlias = new("Primary_US");
        ProviderAlias lowerAlias = new("primary_us");
        KeyName upperKey = new("Master.Key-01");

        Assert.Multiple(() =>
        {
            Assert.That(upperAlias, Is.Not.EqualTo(lowerAlias));
            Assert.That(upperAlias.ToString(), Is.EqualTo("Primary_US"));
            Assert.That(upperKey.ToString(), Is.EqualTo("Master.Key-01"));
            Assert.That(KeyName.TryParse("Master.Key-01", out _), Is.True);
        });
    }

    /// <summary>
    /// Rejects whitespace, path separators, controls and potentially ambiguous names.
    /// </summary>
    [TestCase("")]
    [TestCase(" name")]
    [TestCase("name ")]
    [TestCase("1invalid")]
    [TestCase("slash/name")]
    [TestCase("slash\\name")]
    [TestCase("bad:name")]
    [TestCase("bad\tname")]
    [TestCase("ключ")]
    public void UnsafeNamesAreRejected(string name)
    {
        Assert.Multiple(() =>
        {
            Assert.That(ProviderAlias.TryParse(name, out _), Is.False);
            Assert.That(KeyName.TryParse(name, out _), Is.False);
        });
    }

    /// <summary>
    /// Enforces the maximum length for public names and unambiguous token grammar.
    /// </summary>
    [Test]
    public void NamesAndTokensEnforceLengthAndGrammar()
    {
        Assert.Multiple(() =>
        {
            Assert.That(KeyName.TryParse("a" + new string('b', 127), out _), Is.True);
            Assert.That(KeyName.TryParse("a" + new string('b', 128), out _), Is.False);
            Assert.That(ProviderAlias.TryParse("a" + new string('b', 128), out _), Is.False);
            Assert.That(AlgorithmId.TryParse("AES-256-GCM", out _), Is.False);
            Assert.That(AlgorithmId.TryParse("aes--256", out _), Is.False);
            Assert.That(AlgorithmId.TryParse("aes-", out _), Is.False);
            Assert.That(CapabilityId.TryParse(".encrypt", out _), Is.False);
            Assert.That(CapabilityId.TryParse("encrypt", out _), Is.True);
        });
    }

    /// <summary>
    /// Ensures key identities and aliases are independent of the caller's locale.
    /// </summary>
    [Test]
    public void IdentityParsingIsCultureInvariant()
    {
        CultureInfo original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
            Assert.That(ProviderId.Parse(Canonical).ToString(), Is.EqualTo(Canonical));
            Assert.That(new ProviderAlias("ID").ToString(), Is.EqualTo("ID"));
            Assert.That(new KeyName("INFO").ToString(), Is.EqualTo("INFO"));
            Assert.That(WellKnownAlgorithms.Aes256Gcm.ToString(), Is.EqualTo("aes-256-gcm"));
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }
}
