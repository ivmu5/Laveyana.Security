using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Rollback;
using Laveyana.Security.FileSystem.Storage;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

public sealed partial class FileSystemKeyStoreTests
{
    private async Task<(Guid StoreId, RollbackPreparedWrite Write)> NewPreparedWriteAsync()
    {
        FileSystemKeyStore store = await Open();
        (Guid storeId, byte[] before) = await CurrentSnapshotAsync();
        Assert.That((await store.TryCreateAsync(await CreateRequest(KeyId.New(), _name))).Status,
            Is.EqualTo(Laveyana.Security.Abstractions.Storage.KeyStoreMutationStatus.Applied));
        byte[] after = (await CurrentSnapshotAsync()).Bytes;
        RollbackPreparedWrite write = new(Checkpoint(storeId, 1, before), Checkpoint(storeId, 2, after),
            new RollbackRequestId(Guid.NewGuid()), new RollbackRequestId(Guid.NewGuid()), after);
        return (storeId, write);
    }

    private (LinuxSecureDirectory? Linux, WindowsSecureDirectory? Windows) OpenJournalDirectory()
    {
        if (OperatingSystem.IsLinux())
        {
            return (LinuxSecureDirectory.Open(_root), null);
        }

        if (OperatingSystem.IsWindows())
        {
            return (null, WindowsSecureDirectory.Open(_root));
        }

        throw new PlatformNotSupportedException();
    }

    [Test]
    public async Task RollbackCandidateJournalPersistsExactSnapshotAndTwoStableRequestIds()
    {
        (Guid storeId, RollbackPreparedWrite write) = await NewPreparedWriteAsync();
        byte[] committed = await File.ReadAllBytesAsync(Path.Combine(_root, "store.lsfs"));
        (LinuxSecureDirectory? linux, WindowsSecureDirectory? windows) = OpenJournalDirectory();
        using LinuxSecureDirectory? linuxOwner = linux;
        using WindowsSecureDirectory? windowsOwner = windows;
        {
            using FileStream held = (linux is not null
                ? linux.TryAcquireLock(".store.lock", false)
                : windows!.TryAcquireLock(".store.lock", false))
                ?? throw new InvalidOperationException("Store lock unavailable.");
            Assert.That(await RollbackCandidateJournal.ReadAsync(linux, windows, _protector, storeId), Is.Null);
            await RollbackCandidateJournal.StageAsync(linux, windows, _protector, write);
            RollbackPreparedWrite? read = await RollbackCandidateJournal.ReadAsync(
                linux, windows, _protector, storeId);
            Assert.That(read, Is.Not.Null);
            RollbackPreparedWrite recovered = read ?? throw new InvalidDataException("Missing staged record.");
            Assert.Multiple(() =>
            {
                Assert.That(recovered.Expected.Matches(write.Expected), Is.True);
                Assert.That(recovered.Prepared.Matches(write.Prepared), Is.True);
                Assert.That(recovered.PrepareRequestId.Equals(write.PrepareRequestId), Is.True);
                Assert.That(recovered.FinalizeRequestId.Equals(write.FinalizeRequestId), Is.True);
                Assert.That(recovered.ExportCandidateCopy(), Is.EqualTo(write.ExportCandidateCopy()));
            });
        }

        Assert.That(await File.ReadAllBytesAsync(Path.Combine(_root, "store.lsfs")), Is.EqualTo(committed));
        // A regular writable open's abandoned .pending-* cleanup must not erase the intent.
        await Open();
        Assert.That(File.Exists(Path.Combine(_root, RollbackCandidateJournal.CandidateName)), Is.True);
        Assert.That(File.Exists(Path.Combine(_root, RollbackCandidateJournal.IntentName)), Is.True);
    }

    [Test]
    public async Task RollbackCandidateJournalRefusesOverwriteOfUnresolvedGeneration()
    {
        (Guid storeId, RollbackPreparedWrite write) = await NewPreparedWriteAsync();
        (LinuxSecureDirectory? linux, WindowsSecureDirectory? windows) = OpenJournalDirectory();
        using LinuxSecureDirectory? linuxOwner = linux;
        using WindowsSecureDirectory? windowsOwner = windows;
        {
            using FileStream held = (linux is not null
                ? linux.TryAcquireLock(".store.lock", false)
                : windows!.TryAcquireLock(".store.lock", false))
                ?? throw new InvalidOperationException("Store lock unavailable.");
            await RollbackCandidateJournal.StageAsync(linux, windows, _protector, write);
            Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await RollbackCandidateJournal.StageAsync(linux, windows, _protector, write));
            RollbackPreparedWrite? persisted = await RollbackCandidateJournal.ReadAsync(
                linux, windows, _protector, storeId);
            Assert.That(persisted?.PrepareRequestId.Equals(write.PrepareRequestId), Is.True);
        }
    }

    [Test]
    public async Task RollbackCandidateJournalRejectsTamperedCandidate()
    {
        (Guid storeId, RollbackPreparedWrite write) = await NewPreparedWriteAsync();
        (LinuxSecureDirectory? linux, WindowsSecureDirectory? windows) = OpenJournalDirectory();
        using LinuxSecureDirectory? linuxOwner = linux;
        using WindowsSecureDirectory? windowsOwner = windows;
        {
            using FileStream held = (linux is not null
                ? linux.TryAcquireLock(".store.lock", false)
                : windows!.TryAcquireLock(".store.lock", false))
                ?? throw new InvalidOperationException("Store lock unavailable.");
            await RollbackCandidateJournal.StageAsync(linux, windows, _protector, write);
            string path = Path.Combine(_root, RollbackCandidateJournal.CandidateName);
            byte[] bytes = await File.ReadAllBytesAsync(path);
            bytes[20] ^= 0x40;
            await File.WriteAllBytesAsync(path, bytes);
            Assert.ThrowsAsync<InvalidDataException>(async () =>
                await RollbackCandidateJournal.ReadAsync(linux, windows, _protector, storeId));
        }
    }

    [Test]
    public async Task RollbackCandidateJournalRejectsTamperedAuthenticatedIntent()
    {
        (Guid storeId, RollbackPreparedWrite write) = await NewPreparedWriteAsync();
        (LinuxSecureDirectory? linux, WindowsSecureDirectory? windows) = OpenJournalDirectory();
        using LinuxSecureDirectory? linuxOwner = linux;
        using WindowsSecureDirectory? windowsOwner = windows;
        {
            using FileStream held = (linux is not null
                ? linux.TryAcquireLock(".store.lock", false)
                : windows!.TryAcquireLock(".store.lock", false))
                ?? throw new InvalidOperationException("Store lock unavailable.");
            await RollbackCandidateJournal.StageAsync(linux, windows, _protector, write);
            string path = Path.Combine(_root, RollbackCandidateJournal.IntentName);
            byte[] bytes = await File.ReadAllBytesAsync(path);
            bytes[20] ^= 0x40;
            await File.WriteAllBytesAsync(path, bytes);
            Assert.ThrowsAsync<InvalidDataException>(async () =>
                await RollbackCandidateJournal.ReadAsync(linux, windows, _protector, storeId));
        }
    }

    [Test]
    public async Task RollbackCandidateJournalFailsClosedOnPartialStageAndKeepsEvidence()
    {
        (Guid storeId, RollbackPreparedWrite write) = await NewPreparedWriteAsync();
        (LinuxSecureDirectory? linux, WindowsSecureDirectory? windows) = OpenJournalDirectory();
        using LinuxSecureDirectory? linuxOwner = linux;
        using WindowsSecureDirectory? windowsOwner = windows;
        {
            using FileStream held = (linux is not null
                ? linux.TryAcquireLock(".store.lock", false)
                : windows!.TryAcquireLock(".store.lock", false))
                ?? throw new InvalidOperationException("Store lock unavailable.");
            await RollbackCandidateJournal.StageAsync(linux, windows, _protector, write);
            windows?.Remove(RollbackCandidateJournal.IntentName);
            if (linux is not null)
            {
                linux.Remove(RollbackCandidateJournal.IntentName);
            }

            Assert.ThrowsAsync<InvalidDataException>(async () =>
                await RollbackCandidateJournal.ReadAsync(linux, windows, _protector, storeId));
        }

        await Open();
        Assert.That(File.Exists(Path.Combine(_root, RollbackCandidateJournal.CandidateName)), Is.True);
    }

    [Test]
    public async Task RollbackCandidateJournalBindsUuidAndRejectsIncorrectCheckpoint()
    {
        (Guid storeId, RollbackPreparedWrite write) = await NewPreparedWriteAsync();
        Assert.Throws<ArgumentException>(() => new RollbackPreparedWrite(write.Expected,
            Checkpoint(storeId, 3, write.ExportCandidateCopy()), write.PrepareRequestId,
            write.FinalizeRequestId, write.ExportCandidateCopy()));
        Assert.Throws<ArgumentException>(() => new RollbackPreparedWrite(write.Expected,
            write.Prepared, write.PrepareRequestId, write.PrepareRequestId, write.ExportCandidateCopy()));
        Assert.Throws<ArgumentException>(() => new RollbackPreparedWrite(write.Expected,
            Checkpoint(storeId, 2, new byte[24]), write.PrepareRequestId,
            write.FinalizeRequestId, write.ExportCandidateCopy()));

        (LinuxSecureDirectory? linux, WindowsSecureDirectory? windows) = OpenJournalDirectory();
        using LinuxSecureDirectory? linuxOwner = linux;
        using WindowsSecureDirectory? windowsOwner = windows;
        {
            using FileStream held = (linux is not null
                ? linux.TryAcquireLock(".store.lock", false)
                : windows!.TryAcquireLock(".store.lock", false))
                ?? throw new InvalidOperationException("Store lock unavailable.");
            await RollbackCandidateJournal.StageAsync(linux, windows, _protector, write);
            CryptographicException? failure = null;
            try
            {
                await RollbackCandidateJournal.ReadAsync(linux, windows, _protector, Guid.NewGuid());
            }
            catch (CryptographicException error)
            {
                failure = error;
            }

            Assert.That(failure, Is.Not.Null);
        }
    }
}
