using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>
/// Guards immutable descriptors, lifecycle metadata invariants and capability IDs.
/// </summary>
[TestFixture]
internal sealed class DomainModelTests
{
    private static readonly ProviderId Provider = ProviderId.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly KeyId Key = KeyId.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly SecretId Secret = SecretId.Parse("33333333-3333-4333-8333-333333333333");

    /// <summary>
    /// Confirms logical descriptors are immutable values and preserve the alias as metadata only.
    /// </summary>
    [Test]
    public void LogicalKeyDescriptorHasValueSemantics()
    {
        KeyDescriptor first = new(Provider, Key, new KeyName("Master"), KeyKind.Symmetric, LogicalKeyState.Active, new KeyVersion(1));
        KeyDescriptor same = new(Provider, Key, new KeyName("Master"), KeyKind.Symmetric, LogicalKeyState.Active, new KeyVersion(1));
        KeyDescriptor renamed = new(Provider, Key, new KeyName("NewName"), KeyKind.Symmetric, LogicalKeyState.Active, new KeyVersion(1));

        Assert.Multiple(() =>
        {
            Assert.That(first, Is.EqualTo(same));
            Assert.That(first.GetHashCode(), Is.EqualTo(same.GetHashCode()));
            Assert.That(first, Is.Not.EqualTo(renamed));
            Assert.That(first.ProviderId, Is.EqualTo(renamed.ProviderId));
            Assert.That(first.KeyId, Is.EqualTo(renamed.KeyId));
            Assert.That(first.ActiveVersion, Is.EqualTo(new KeyVersion(1)));
            Assert.That(first.ToString(), Is.EqualTo("KeyDescriptor"));
        });
    }

    /// <summary>
    /// Enforces state constraints without yet implementing state transitions.
    /// </summary>
    [Test]
    public void LogicalDescriptorRequiresExactlyAnActiveVersionForActiveState()
    {
        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentException>(() => new KeyDescriptor(Provider, Key, null, KeyKind.Symmetric, LogicalKeyState.Active, null));
            Assert.Throws<ArgumentException>(() => new KeyDescriptor(Provider, Key, null, KeyKind.Symmetric, LogicalKeyState.Retired, new KeyVersion(1)));
            Assert.Throws<ArgumentException>(() => new KeyDescriptor(Provider, Key, null, KeyKind.Symmetric, LogicalKeyState.Active, default(KeyVersion)));
            Assert.Throws<ArgumentException>(() => new KeyDescriptor(default, Key, null, KeyKind.Symmetric, LogicalKeyState.Active, new KeyVersion(1)));
            Assert.Throws<ArgumentException>(() => new KeyDescriptor(Provider, Key, null, KeyKind.Unspecified, LogicalKeyState.Active, new KeyVersion(1)));
            Assert.Throws<ArgumentException>(() => new KeyDescriptor(Provider, Key, null, KeyKind.Symmetric, (LogicalKeyState)999, new KeyVersion(1)));
            Assert.That(new KeyDescriptor(Provider, Key, null, KeyKind.AsymmetricPrivate, LogicalKeyState.Retired, null).ActiveVersion, Is.Null);
        });
    }

    /// <summary>
    /// Confirms the version snapshot cannot expose or be mutated through a caller-owned array.
    /// </summary>
    [Test]
    public void VersionDescriptorDefensivelyCopiesAndCanonicalizesCapabilities()
    {
        KeyReference reference = new(Provider, Key, new KeyVersion(2));
        CapabilityId[] original = [WellKnownCapabilities.Sign, WellKnownCapabilities.VerifySignature];
        KeyVersionDescriptor descriptor = new(reference, KeyVersionState.Pending, WellKnownAlgorithms.EcdsaP256Sha256, original);
        KeyVersionDescriptor reversed = new(reference, KeyVersionState.Pending, WellKnownAlgorithms.EcdsaP256Sha256,
            [WellKnownCapabilities.VerifySignature, WellKnownCapabilities.Sign]);
        original[0] = WellKnownCapabilities.ExportMaterial;

        Assert.Multiple(() =>
        {
            Assert.That(descriptor, Is.EqualTo(reversed));
            Assert.That(descriptor.GetHashCode(), Is.EqualTo(reversed.GetHashCode()));
            Assert.That(descriptor.Capabilities, Has.Count.EqualTo(2));
            Assert.That(descriptor.Capabilities, Does.Contain(WellKnownCapabilities.Sign));
            Assert.That(descriptor.Capabilities, Does.Not.Contain(WellKnownCapabilities.ExportMaterial));
            Assert.That(descriptor.Capabilities, Is.InstanceOf<IReadOnlyList<CapabilityId>>());
            Assert.That(() => ((IList<CapabilityId>)descriptor.Capabilities)[0] = WellKnownCapabilities.ExportMaterial,
                Throws.TypeOf<NotSupportedException>());
        });
    }

    /// <summary>
    /// Rejects uninitialized and duplicate capabilities rather than hiding them.
    /// </summary>
    [Test]
    public void VersionDescriptorRejectsInvalidValues()
    {
        KeyReference reference = new(Provider, Key, new KeyVersion(1));
        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentException>(() => new KeyVersionDescriptor(default, KeyVersionState.Active, WellKnownAlgorithms.Aes256Gcm, []));
            Assert.Throws<ArgumentException>(() => new KeyVersionDescriptor(reference, KeyVersionState.Unspecified, WellKnownAlgorithms.Aes256Gcm, []));
            Assert.Throws<ArgumentException>(() => new KeyVersionDescriptor(reference, KeyVersionState.Active, default, []));
            Assert.Throws<ArgumentException>(() => new KeyVersionDescriptor(reference, KeyVersionState.Active, WellKnownAlgorithms.Aes256Gcm,
                [WellKnownCapabilities.Encrypt, WellKnownCapabilities.Encrypt]));
            Assert.Throws<ArgumentException>(() => new KeyVersionDescriptor(reference, KeyVersionState.Active, WellKnownAlgorithms.Aes256Gcm, [default(CapabilityId)]));
            Assert.Throws<ArgumentException>(() => new KeyVersionDescriptor(reference, KeyVersionState.Active, WellKnownAlgorithms.Aes256Gcm,
                Enumerable.Range(0, 65).Select(index => new CapabilityId($"custom-{index}"))));
        });
    }

    /// <summary>
    /// Checks that a secret descriptor contains only stable, defined provider/secret identity.
    /// </summary>
    [Test]
    public void SecretDescriptorIsOpaqueAndValidated()
    {
        SecretReference reference = new(Provider, Secret);
        SecretDescriptor first = new(reference);
        SecretDescriptor same = new(SecretReference.Parse(reference.ToString()));
        Assert.Multiple(() =>
        {
            Assert.That(first, Is.EqualTo(same));
            Assert.That(first.Reference, Is.EqualTo(reference));
            Assert.That(first.ToString(), Is.EqualTo("SecretDescriptor [REDACTED]"));
            Assert.Throws<ArgumentException>(() => new SecretDescriptor(default));
        });
    }

    /// <summary>
    /// Checks that well-known tokens are stable strings instead of CLR enum values.
    /// </summary>
    [Test]
    public void AlgorithmsAndCapabilitiesHaveStableTextIds()
    {
        Assert.Multiple(() =>
        {
            Assert.That(WellKnownAlgorithms.Aes256Gcm, Is.EqualTo(new AlgorithmId("aes-256-gcm")));
            Assert.That(WellKnownAlgorithms.HkdfSha256, Is.EqualTo(new AlgorithmId("hkdf-sha-256")));
            Assert.That(WellKnownCapabilities.OpenMaterial, Is.Not.EqualTo(WellKnownCapabilities.ExportMaterial));
            Assert.That(WellKnownCapabilities.ExportMaterial.ToString(), Is.EqualTo("export-material"));
            Assert.That(new CapabilityId("export-material").GetHashCode(), Is.EqualTo(WellKnownCapabilities.ExportMaterial.GetHashCode()));
        });
    }
}
