using System.Text;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Recovery;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Locks down the independently generated, persistent v1 recovery wire format.</summary>
[TestFixture]
internal sealed class PortableKeyRecoveryCompatibilityTests
{
    [Test]
    public void IndependentlyGeneratedV1FixtureRemainsReadable()
    {
        // Public, deterministic test values. Never replace this fixture using the product codec.
        string fixturePath = Path.Combine(TestContext.CurrentContext.TestDirectory,
            "Fixtures", "portable-key-recovery-v1.hex");
        byte[] package = Convert.FromHexString(File.ReadAllText(fixturePath).Trim());
        byte[] expected = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        using SensitiveMaterialLease secret = SensitiveMaterialLease.CreateCopy(expected);
        byte[] scope = Encoding.UTF8.GetBytes(
            "com.example.application|data-key|11111111-1111-4111-8111-111111111111|1");

        using SensitiveMaterialLease recovered = PortableKeyRecovery.Unprotect(package, secret, scope);
        byte[]? actual = null;
        recovered.UseMaterial(bytes => actual = bytes.ToArray());
        Assert.That(actual, Is.EqualTo(expected));
    }
}
