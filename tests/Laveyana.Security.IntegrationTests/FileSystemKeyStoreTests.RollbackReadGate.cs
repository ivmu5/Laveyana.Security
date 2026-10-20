using NUnit.Framework;
using Laveyana.Security.Abstractions.Persistence;
using Laveyana.Security.Abstractions.Rollback;
using Laveyana.Security.FileSystem.Storage;

namespace Laveyana.Security.IntegrationTests;

public sealed partial class FileSystemKeyStoreTests
{
    private async Task<(Guid StoreId, byte[] Bytes)> CurrentSnapshotAsync()
    {
        byte[] bootstrap = await File.ReadAllBytesAsync(Path.Combine(_root, "bootstrap.lspb"));
        Guid storeId = ProtectorBootstrapRecord.Decode(bootstrap).StoreInstanceId;
        byte[] snapshot = await File.ReadAllBytesAsync(Path.Combine(_root, "store.lsfs"));
        return (storeId, snapshot);
    }

    private static RollbackCheckpoint Checkpoint(Guid storeId, ulong sequence, byte[] snapshot) =>
        new(storeId, sequence, RollbackSnapshotDigest.Compute(storeId, snapshot));

    private FileSystemKeyStoreOptions RollbackReadOptions(Guid storeId, IKeyStoreRollbackAuthority authority) =>
        new(_root) { ExpectedStoreInstanceId = storeId, RollbackAuthority = authority };

    [Test]
    public async Task RollbackReadGateAcceptsExactAuthenticatedCommittedSnapshot()
    {
        FileSystemKeyStore writer = await Open();
        await writer.TryCreateAsync(await CreateRequest(Laveyana.Security.Abstractions.Identifiers.KeyId.New(), _name));
        (Guid storeId, byte[] bytes) = await CurrentSnapshotAsync();
        ReadAuthority authority = new(new RollbackAuthorityState(Checkpoint(storeId, 4, bytes)));
        using FileSystemKeyStore reader = await FileSystemKeyStore.OpenAsync(
            RollbackReadOptions(storeId, authority), _protector);
        Assert.That(await reader.FindByNameAsync(_provider, _name), Is.Not.Null);
        Assert.That(reader.Capabilities.ProvidesRollbackProtection, Is.False);
        Assert.That(authority.Reads, Is.GreaterThanOrEqualTo(2)); // Open + read
    }

    [Test]
    public async Task RollbackReadGateChecksFreshnessAgainOnEveryRead()
    {
        FileSystemKeyStore writer = await Open();
        (Guid storeId, byte[] before) = await CurrentSnapshotAsync();
        ReadAuthority authority = new(new RollbackAuthorityState(Checkpoint(storeId, 1, before)));
        using FileSystemKeyStore reader = await FileSystemKeyStore.OpenAsync(
            RollbackReadOptions(storeId, authority), _protector);
        Assert.That(await reader.FindByNameAsync(_provider, _name), Is.Null);
        await writer.TryCreateAsync(await CreateRequest(Laveyana.Security.Abstractions.Identifiers.KeyId.New(), _name));
        Assert.ThrowsAsync<InvalidDataException>(async () => await reader.FindByNameAsync(_provider, _name));
    }

    [Test]
    public async Task RollbackReadGateRejectsReplayedValidOldSnapshot()
    {
        FileSystemKeyStore writer = await Open();
        (Guid storeId, byte[] before) = await CurrentSnapshotAsync();
        await writer.TryCreateAsync(await CreateRequest(Laveyana.Security.Abstractions.Identifiers.KeyId.New(), _name));
        byte[] current = (await CurrentSnapshotAsync()).Bytes;
        ReadAuthority authority = new(new RollbackAuthorityState(Checkpoint(storeId, 2, current)));
        await File.WriteAllBytesAsync(Path.Combine(_root, "store.lsfs"), before);
        Assert.ThrowsAsync<InvalidDataException>(async () => await FileSystemKeyStore.OpenAsync(
            RollbackReadOptions(storeId, authority), _protector));
    }

    [Test]
    public async Task RollbackReadGateRejectsBothPendingOldAndPendingNewSnapshot()
    {
        FileSystemKeyStore writer = await Open();
        (Guid storeId, byte[] before) = await CurrentSnapshotAsync();
        await writer.TryCreateAsync(await CreateRequest(Laveyana.Security.Abstractions.Identifiers.KeyId.New(), _name));
        byte[] current = (await CurrentSnapshotAsync()).Bytes;
        ReadAuthority authority = new(new RollbackAuthorityState(
            Checkpoint(storeId, 1, before), Checkpoint(storeId, 2, current)));
        Assert.ThrowsAsync<InvalidDataException>(async () => await FileSystemKeyStore.OpenAsync(
            RollbackReadOptions(storeId, authority), _protector));
        await File.WriteAllBytesAsync(Path.Combine(_root, "store.lsfs"), before);
        Assert.ThrowsAsync<InvalidDataException>(async () => await FileSystemKeyStore.OpenAsync(
            RollbackReadOptions(storeId, authority), _protector));
    }

    [Test]
    public async Task RollbackReadGateRejectsMissingForeignAndUnavailableAuthority()
    {
        await Open();
        (Guid storeId, byte[] bytes) = await CurrentSnapshotAsync();
        ReadAuthority authority = new(null);
        Assert.ThrowsAsync<InvalidDataException>(async () => await FileSystemKeyStore.OpenAsync(
            RollbackReadOptions(storeId, authority), _protector));
        authority.State = new RollbackAuthorityState(Checkpoint(Guid.NewGuid(), 1, bytes));
        Assert.ThrowsAsync<InvalidDataException>(async () => await FileSystemKeyStore.OpenAsync(
            RollbackReadOptions(storeId, authority), _protector));
        authority.FailReads = true;
        Assert.ThrowsAsync<IOException>(async () => await FileSystemKeyStore.OpenAsync(
            RollbackReadOptions(storeId, authority), _protector));
    }

    [Test]
    public async Task RollbackReadGateRequiresReadOnlyAndPinnedUuidBeforeTouchingStore()
    {
        await Open();
        (Guid storeId, byte[] bytes) = await CurrentSnapshotAsync();
        ReadAuthority authority = new(new RollbackAuthorityState(Checkpoint(storeId, 1, bytes)));
        FileSystemKeyStoreOptions writable = new(_root)
        {
            EnableExperimentalWrites = true, ExpectedStoreInstanceId = storeId,
            RollbackAuthority = authority
        };
        Assert.ThrowsAsync<ArgumentException>(async () => await FileSystemKeyStore.OpenAsync(
            writable, _protector));
        Assert.ThrowsAsync<ArgumentException>(async () => await FileSystemKeyStore.OpenAsync(
            new FileSystemKeyStoreOptions(_root) { RollbackAuthority = authority }, _protector));
        Assert.That(authority.Reads, Is.Zero);
    }

    [Test]
    public async Task RollbackReadGateDoesNotMutateAnyStoreFile()
    {
        await Open();
        (Guid storeId, byte[] bytes) = await CurrentSnapshotAsync();
        ReadAuthority authority = new(new RollbackAuthorityState(Checkpoint(storeId, 1, bytes)));
        string[] entries = Directory.GetFileSystemEntries(_root);
        byte[] bootstrap = await File.ReadAllBytesAsync(Path.Combine(_root, "bootstrap.lspb"));
        using (FileSystemKeyStore reader = await FileSystemKeyStore.OpenAsync(
            RollbackReadOptions(storeId, authority), _protector))
        {
            Assert.That(await reader.FindByNameAsync(_provider, _name), Is.Null);
            Assert.ThrowsAsync<InvalidOperationException>(async () => await reader.TryDeleteAsync(
                _provider, Laveyana.Security.Abstractions.Identifiers.KeyId.New(), new(1)));
        }

        Assert.That(Directory.GetFileSystemEntries(_root), Is.EquivalentTo(entries));
        Assert.That(await File.ReadAllBytesAsync(Path.Combine(_root, "store.lsfs")), Is.EqualTo(bytes));
        Assert.That(await File.ReadAllBytesAsync(Path.Combine(_root, "bootstrap.lspb")), Is.EqualTo(bootstrap));
    }

    private sealed class ReadAuthority(RollbackAuthorityState? state) : IKeyStoreRollbackAuthority
    {
        public RollbackAuthorityState? State { get; set; } = state;
        public bool FailReads { get; set; }
        public int Reads { get; private set; }

        public ValueTask<RollbackAuthorityState?> ReadAsync(Guid storeInstanceId,
            CancellationToken cancellationToken = default)
        {
            Reads++;
            if (FailReads)
            {
                throw new IOException("Authority is unavailable.");
            }
            return ValueTask.FromResult(State);
        }

        public ValueTask<bool> TryEnrollAsync(RollbackCheckpoint initial,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<bool> TryPrepareAsync(RollbackCheckpoint expected, RollbackCheckpoint next,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public ValueTask<bool> TryFinalizeAsync(RollbackCheckpoint expected, RollbackCheckpoint prepared,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}
