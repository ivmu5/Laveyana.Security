using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Persistence;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Lifecycle;
using Laveyana.Security.Software;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Independent golden fixtures, legacy migration, fail-closed schemas and monotonic mappings.</summary>
[TestFixture]
internal sealed class PersistentSchemaTests
{
    private static readonly ProviderId Provider = ProviderId.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly KeyId Key = KeyId.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly KeyName Name = new("Master");

    private static byte[] Fixture(string name) => Convert.FromHexString(
        File.ReadAllText(Path.Combine(TestContext.CurrentContext.TestDirectory, "Fixtures", name)).Trim());

    private static SoftwareKeyMetadata Sample()
    {
        KeyLifecycleSnapshot history = new(Provider, Key, LogicalKeyState.Active, new KeyVersion(7),
        [new KeyLifecycleVersion(new KeyVersion(1), KeyVersionState.Active),
         new KeyLifecycleVersion(new KeyVersion(5), KeyVersionState.Deleted)]);
        return new SoftwareKeyMetadata(Name, KeyKind.Symmetric, WellKnownAlgorithms.HmacSha256,
            [WellKnownCapabilities.Mac, WellKnownCapabilities.VerifyMac], history);
    }

    private static byte[] Export(SensitiveMaterialLease lease)
    {
        byte[]? result = null;
        lease.UseMaterial(bytes => result = bytes.ToArray());
        return result!;
    }

    [Test]
    public void V2CanonicalGoldenEncodingAndHistoryGaps()
    {
        using SensitiveMaterialLease encoded = SoftwareKeyMetadataCodec.Encode(Sample());
        byte[] bytes = Export(encoded);
        Assert.That(bytes, Is.EqualTo(Fixture("metadata-v2.hex")));
        Assert.That(SoftwareKeyMetadataCodec.ReadFormatVersion(encoded), Is.EqualTo((ushort)2));
        using SensitiveMaterialLease loaded = SensitiveMaterialLease.CreateCopy(bytes);
        SoftwareKeyMetadata parsed = SoftwareKeyMetadataCodec.Decode(loaded, Provider, Key, Name);
        Assert.That(parsed.Lifecycle.HighWaterMark.Value, Is.EqualTo(7));
        Assert.That(parsed.Lifecycle.Versions.Select(x => x.Version.Value), Is.EqualTo(new long[] { 1, 5 }));
        Assert.That(parsed.Lifecycle.ActiveVersion, Is.EqualTo(new KeyVersion(1)));
    }

    [Test]
    public void LegacyGoldenMigrationIsDeterministicAndPreservesTombstones()
    {
        using SensitiveMaterialLease legacy = LegacySoftwareKeyMetadataV1Codec.Encode(Sample());
        Assert.That(Export(legacy), Is.EqualTo(Fixture("metadata-v1.hex")));
        Assert.That(SoftwareKeyMetadataCodec.ReadFormatVersion(legacy), Is.EqualTo((ushort)1));
        using SensitiveMaterialLease migrated = SoftwareKeyMetadataCodec.MigrateToCurrent(legacy, Provider, Key, Name);
        Assert.That(Export(migrated), Is.EqualTo(Fixture("metadata-v2.hex")));
        using SensitiveMaterialLease migratedAgain = SoftwareKeyMetadataCodec.MigrateToCurrent(migrated, Provider, Key, Name);
        Assert.That(Export(migratedAgain), Is.EqualTo(Export(migrated)));
        Assert.That(SoftwareKeyMetadataCodec.ReadFormatVersion(legacy), Is.EqualTo((ushort)1));
    }

    [Test]
    public void MetadataRejectsFutureVersionFlagsWrongIdentityAndCorruption()
    {
        byte[] golden = Fixture("metadata-v2.hex");
        static void MustReject(byte[] bytes)
        {
            using SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy(bytes);
            Assert.Throws<InvalidOperationException>(() => SoftwareKeyMetadataCodec.Decode(lease, Provider, Key, Name));
        }

        byte[] flags = (byte[])golden.Clone();
        flags[6] = 1;
        MustReject(flags);
        byte[] future = (byte[])golden.Clone();
        future[4] = 3;
        using (SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy(future))
        {
            Assert.Throws<NotSupportedException>(() => SoftwareKeyMetadataCodec.Decode(lease, Provider, Key, Name));
        }

        byte[] wrongName = (byte[])golden.Clone();
        wrongName[88] ^= 1;
        MustReject(wrongName);
        MustReject(golden[..^1]);
        MustReject([.. golden, 0]);
        using SensitiveMaterialLease clean = SensitiveMaterialLease.CreateCopy(golden);
        Assert.Throws<InvalidOperationException>(() => SoftwareKeyMetadataCodec.Decode(clean,
            ProviderId.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), Key, Name));
    }

    [Test]
    public void NoncanonicalOrderingAndInvalidStateAreRejected()
    {
        byte[] golden = Fixture("metadata-v2.hex");
        int offset = Find(golden, "active"u8.ToArray());
        Assert.That(offset, Is.GreaterThan(0));
        byte[] changed = (byte[])golden.Clone();
        changed[offset] = (byte)'A';
        using SensitiveMaterialLease lease = SensitiveMaterialLease.CreateCopy(changed);
        Assert.Throws<InvalidOperationException>(() => SoftwareKeyMetadataCodec.Decode(lease, Provider, Key, Name));
    }

    private static int Find(byte[] haystack, byte[] needle) => haystack.AsSpan().IndexOf(needle);

    [Test]
    public void RetentionRoundTripPreservesExactUtcTicks()
    {
        DateTimeOffset deadline = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
        KeyLifecycleSnapshot state = new(Provider, Key, LogicalKeyState.Active, new KeyVersion(9),
            [new KeyLifecycleVersion(new KeyVersion(9), KeyVersionState.Active,
                new KeyRetentionConstraint(deadline, true))]);
        SoftwareKeyMetadata source = new(Name, KeyKind.Symmetric, WellKnownAlgorithms.HmacSha256,
            [WellKnownCapabilities.Mac], state);
        using SensitiveMaterialLease encoded = SoftwareKeyMetadataCodec.Encode(source);
        SoftwareKeyMetadata decoded = SoftwareKeyMetadataCodec.Decode(encoded, Provider, Key, Name);
        Assert.That(decoded.Lifecycle.Find(new KeyVersion(9))!.Retention.RetainUntilUtc, Is.EqualTo(deadline));
        Assert.That(decoded.Lifecycle.Find(new KeyVersion(9))!.Retention.IsOnHold, Is.True);
    }

    [Test]
    public void BootstrapGoldenAndUnknownFutureOrTamperReject()
    {
        ProtectorBootstrapRecord expected = new(Guid.Parse("33333333-3333-4333-8333-333333333333"),
            new ProtectorReference("root", 2));
        byte[] golden = Fixture("protector-bootstrap-v1.hex");
        Assert.That(expected.Encode(), Is.EqualTo(golden));
        ProtectorBootstrapRecord decoded = ProtectorBootstrapRecord.Decode(golden);
        Assert.That(decoded.StoreInstanceId, Is.EqualTo(expected.StoreInstanceId));
        Assert.That(decoded.Protector, Is.EqualTo(expected.Protector));
        byte[] future = (byte[])golden.Clone();
        future[4] = 2;
        Assert.Throws<NotSupportedException>(() => ProtectorBootstrapRecord.Decode(future));
        byte[] flags = (byte[])golden.Clone();
        flags[7] = 1;
        Assert.Throws<InvalidOperationException>(() => ProtectorBootstrapRecord.Decode(flags));
        Assert.Throws<InvalidOperationException>(() => ProtectorBootstrapRecord.Decode(golden[..^1]));
    }

    [Test]
    public void NonceCheckpointGoldenMappingAndMonotonicValidation()
    {
        KeyReference reference = new(Provider, Key, new KeyVersion(5));
        NonceAllocationCheckpoint checkpoint = new(reference, 0x1234ABCDu, 192, 9);
        byte[] golden = Fixture("nonce-checkpoint-v1.hex");
        Assert.That(checkpoint.Encode(), Is.EqualTo(golden));
        NonceAllocationCheckpoint reloaded = NonceAllocationCheckpoint.Decode(golden);
        Assert.That(reloaded.Reference, Is.EqualTo(reference));
        Assert.That(reloaded.Prefix, Is.EqualTo(checkpoint.Prefix));
        Assert.That(reloaded.NextCounter, Is.EqualTo(192UL));
        Assert.That(reloaded.AuthorityEpoch, Is.EqualTo(9UL));
        new NonceAllocationCheckpoint(reference, 0x1234ABCDu, 256, 10).ValidateSuccessor(reloaded);
        Assert.Throws<InvalidOperationException>(() => reloaded.ValidateSuccessor(reloaded));
        Assert.Throws<InvalidOperationException>(() =>
            new NonceAllocationCheckpoint(reference, 0x1234ABCDu, 191, 10).ValidateSuccessor(reloaded));
        Assert.Throws<InvalidOperationException>(() =>
            new NonceAllocationCheckpoint(reference, 42, 256, 10).ValidateSuccessor(reloaded));
        byte[] future = (byte[])golden.Clone();
        future[4] = 2;
        Assert.Throws<NotSupportedException>(() => NonceAllocationCheckpoint.Decode(future));
        Assert.Throws<InvalidOperationException>(() => NonceAllocationCheckpoint.Decode(golden[..^1]));
    }
}
