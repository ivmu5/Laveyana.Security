using NUnit.Framework;
using Laveyana.Security.Abstractions.Persistence;
using Laveyana.Security.Protection;
using Laveyana.Security.FileSystem.Storage;

namespace Laveyana.Security.IntegrationTests;

public sealed partial class FileSystemKeyStoreTests
{
    [TestCase(0L)]
    [TestCase(-1L)]
    [TestCase(long.MinValue)]
    [TestCase(3_000_000_001L)]
    [TestCase(long.MaxValue)]
    public async Task BothOpenModesRejectInvalidLockTimeoutWithoutMutatingStore(long timeoutTicks)
    {
        await Open();
        string snapshotPath = Path.Combine(_root, "store.lsfs");
        string bootstrapPath = Path.Combine(_root, "bootstrap.lspb");
        byte[] snapshotBefore = await File.ReadAllBytesAsync(snapshotPath);
        byte[] bootstrapBefore = await File.ReadAllBytesAsync(bootstrapPath);
        string[] entriesBefore = Directory.GetFileSystemEntries(_root);
        Guid pinnedId = ProtectorBootstrapRecord.Decode(bootstrapBefore).StoreInstanceId;
        TestProtector current = new(2);
        ProtectorGenerationRouter router = new(current,
            [new HistoricalProtectorRegistration(_protector, HistoricalProtectorStatus.LegacyReadOnly)]);
        FileSystemKeyStoreOptions options = new(_root)
        {
            EnableExperimentalWrites = true,
            ExpectedStoreInstanceId = pinnedId,
            LockTimeout = TimeSpan.FromTicks(timeoutTicks)
        };

        Assert.ThrowsAsync<ArgumentException>(async () =>
            await FileSystemKeyStore.OpenAsync(options, _protector));
        Assert.ThrowsAsync<ArgumentException>(async () =>
            await FileSystemKeyStore.OpenForMigrationAsync(options, router, _protector.CurrentReference));

        Assert.That(await File.ReadAllBytesAsync(snapshotPath), Is.EqualTo(snapshotBefore));
        Assert.That(await File.ReadAllBytesAsync(bootstrapPath), Is.EqualTo(bootstrapBefore));
        Assert.That(Directory.GetFileSystemEntries(_root), Is.EquivalentTo(entriesBefore));
    }

    [TestCase(1L)]
    [TestCase(3_000_000_000L)]
    public async Task BothOpenModesAcceptValidLockTimeoutBoundaries(long timeoutTicks)
    {
        await Open();
        Guid pinnedId = ProtectorBootstrapRecord.Decode(
            await File.ReadAllBytesAsync(Path.Combine(_root, "bootstrap.lspb"))).StoreInstanceId;
        TestProtector current = new(2);
        ProtectorGenerationRouter router = new(current,
            [new HistoricalProtectorRegistration(_protector, HistoricalProtectorStatus.LegacyReadOnly)]);
        FileSystemKeyStoreOptions options = new(_root)
        {
            EnableExperimentalWrites = true,
            ExpectedStoreInstanceId = pinnedId,
            LockTimeout = TimeSpan.FromTicks(timeoutTicks)
        };

        using FileSystemKeyStore normal = await FileSystemKeyStore.OpenAsync(options, _protector);
        using FileSystemKeyStore migration = await FileSystemKeyStore.OpenForMigrationAsync(
            options, router, _protector.CurrentReference);

        Assert.That(await normal.FindByNameAsync(_provider, _name), Is.Null);
        Assert.That(await migration.FindByNameAsync(_provider, _name), Is.Null);
    }
}
