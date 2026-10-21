using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.FileSystem.Storage;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

public sealed partial class FileSystemKeyStoreTests
{
    [TestCase(nameof(StoreWriteBoundary.TemporaryCreated), false)]
    [TestCase(nameof(StoreWriteBoundary.DataWritten), false)]
    [TestCase(nameof(StoreWriteBoundary.FileFlushed), false)]
    [TestCase(nameof(StoreWriteBoundary.BeforeRename), false)]
    [TestCase(nameof(StoreWriteBoundary.AfterRename), true)]
    [TestCase(nameof(StoreWriteBoundary.Published), true)]
    public async Task SnapshotPublicationFaultKeepsOneAuthenticatedState(string boundaryName, bool committed)
    {
        StoreWriteBoundary boundary = Enum.Parse<StoreWriteBoundary>(boundaryName);
        await Open();
        byte[] before = (await CurrentSnapshotAsync()).Bytes;
        using FileSystemKeyStore writer = await FileSystemKeyStore.OpenAsync(new(_root)
        {
            EnableExperimentalWrites = true,
            WriteFault = (point, name) =>
            {
                if (name == "store.lsfs" && point == boundary)
                {
                    throw new IOException("Injected publication boundary failure.");
                }
            }
        }, _protector);
        Assert.ThrowsAsync<IOException>(async () => await writer.TryCreateAsync(await CreateRequest(KeyId.New(), _name)));
        using FileSystemKeyStore reader = await FileSystemKeyStore.OpenAsync(new(_root), _protector);
        Assert.That(await reader.FindByNameAsync(_provider, _name), committed ? Is.Not.Null : Is.Null);
        Assert.That((await CurrentSnapshotAsync()).Bytes.AsSpan().SequenceEqual(before), Is.EqualTo(!committed));
    }

    [Test]
    public async Task LinuxDirectoryBarrierFailureIsUncertainAfterVisibleRename()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux directory fsync boundary.");
            return;
        }

        await Open();
        using FileSystemKeyStore writer = await FileSystemKeyStore.OpenAsync(new(_root)
        {
            EnableExperimentalWrites = true,
            WriteFault = (point, name) =>
            {
                if (name == "store.lsfs" && point == StoreWriteBoundary.AfterRename)
                {
                    throw new OperationCanceledException("Cancellation after rename, before directory fsync.");
                }
            }
        }, _protector);
        IOException? failure = Assert.ThrowsAsync<IOException>(async () =>
            await writer.TryCreateAsync(await CreateRequest(KeyId.New(), _name)));
        Assert.That(failure!.Message, Does.Contain("may have committed"));
        Assert.That(failure.InnerException, Is.TypeOf<OperationCanceledException>());
        using FileSystemKeyStore reader = await FileSystemKeyStore.OpenAsync(new(_root), _protector);
        Assert.That(await reader.FindByNameAsync(_provider, _name), Is.Not.Null);
    }

    [Test]
    public async Task LinuxPublicationReportsDirectoryBarrierOnlyAfterRename()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Ignore("Linux directory fsync boundary.");
            return;
        }

        await Open();
        List<StoreWriteBoundary> observed = new();
        using FileSystemKeyStore writer = await FileSystemKeyStore.OpenAsync(new(_root)
        {
            EnableExperimentalWrites = true,
            WriteFault = (point, name) =>
            {
                if (name == "store.lsfs")
                {
                    observed.Add(point);
                }
            }
        }, _protector);
        Assert.That((await writer.TryCreateAsync(await CreateRequest(KeyId.New(), _name))).Status,
            Is.EqualTo(KeyStoreMutationStatus.Applied));
        Assert.That(observed, Is.EqualTo(Enum.GetValues<StoreWriteBoundary>()));
    }

    [TestCase(RollbackCandidateJournal.CandidateName)]
    [TestCase(RollbackCandidateJournal.IntentName)]
    public async Task RollbackInspectionBlocksUnresolvedLocalEvidenceWithoutDeletingIt(string evidenceName)
    {
        FileSystemKeyStore ordinary = await Open();
        (Guid storeId, byte[] snapshot) = await CurrentSnapshotAsync();
        ReadAuthority authority = new(new(Checkpoint(storeId, 1, snapshot)));
        using FileSystemKeyStore inspection = await FileSystemKeyStore.OpenAsync(RollbackReadOptions(storeId, authority), _protector);
        int reads = authority.Reads;
        string path = Path.Combine(_root, evidenceName);
        await File.WriteAllBytesAsync(path, new byte[] { 1 });
        if (OperatingSystem.IsLinux())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        Assert.ThrowsAsync<InvalidDataException>(async () => await inspection.FindByNameAsync(_provider, _name));
        Assert.ThrowsAsync<InvalidDataException>(async () =>
            await FileSystemKeyStore.OpenAsync(RollbackReadOptions(storeId, authority), _protector));
        Assert.That(authority.Reads, Is.EqualTo(reads));
        Assert.That(await File.ReadAllBytesAsync(path), Is.EqualTo(new byte[] { 1 }));
        Assert.That((await CurrentSnapshotAsync()).Bytes, Is.EqualTo(snapshot));
        // Legacy mode remains an explicitly unprotected experiment, never a protected fallback.
        Assert.That(await ordinary.FindByNameAsync(_provider, _name), Is.Null);
        Assert.That(ordinary.Capabilities.ProvidesRollbackProtection, Is.False);
    }

    [TestCase(nameof(StoreWriteBoundary.FileFlushed), RollbackCandidateJournal.CandidateName)]
    [TestCase(nameof(StoreWriteBoundary.AfterRename), RollbackCandidateJournal.CandidateName)]
    [TestCase(nameof(StoreWriteBoundary.FileFlushed), RollbackCandidateJournal.IntentName)]
    [TestCase(nameof(StoreWriteBoundary.AfterRename), RollbackCandidateJournal.IntentName)]
    public async Task JournalBoundaryFailureRetainsPublishedEvidence(string boundaryName, string target)
    {
        StoreWriteBoundary boundary = Enum.Parse<StoreWriteBoundary>(boundaryName);
        (Guid storeId, RollbackPreparedWrite write) = await NewPreparedWriteAsync();
        (LinuxSecureDirectory? linux, WindowsSecureDirectory? windows) = OpenJournalDirectory();
        using LinuxSecureDirectory? linuxOwner = linux;
        using WindowsSecureDirectory? windowsOwner = windows;
        using FileStream held = (linux?.TryAcquireLock(".store.lock", false) ?? windows?.TryAcquireLock(".store.lock", false))!;
        Assert.ThrowsAsync<IOException>(async () => await RollbackCandidateJournal.StageAsync(linux, windows,
            _protector, write, fault: (point, name) =>
            {
                if (point == boundary && name == target)
                {
                    throw new IOException("Injected journal boundary failure.");
                }
            }));
        bool candidate = File.Exists(Path.Combine(_root, RollbackCandidateJournal.CandidateName));
        bool intent = File.Exists(Path.Combine(_root, RollbackCandidateJournal.IntentName));
        bool expectCandidate = target == RollbackCandidateJournal.IntentName || boundary == StoreWriteBoundary.AfterRename;
        bool expectIntent = target == RollbackCandidateJournal.IntentName && boundary == StoreWriteBoundary.AfterRename;
        Assert.That(candidate, Is.EqualTo(expectCandidate));
        Assert.That(intent, Is.EqualTo(expectIntent));
        if (candidate && intent)
        {
            Assert.That((await RollbackCandidateJournal.ReadAsync(linux, windows, _protector, storeId))!.Prepared.Matches(write.Prepared), Is.True);
        }
        else if (candidate)
        {
            Assert.ThrowsAsync<InvalidDataException>(async () => await RollbackCandidateJournal.ReadAsync(linux, windows, _protector, storeId));
        }

        Assert.That(File.Exists(Path.Combine(_root, RollbackCandidateJournal.CandidateName)), Is.EqualTo(candidate));
        Assert.That(File.Exists(Path.Combine(_root, RollbackCandidateJournal.IntentName)), Is.EqualTo(intent));
    }
}
