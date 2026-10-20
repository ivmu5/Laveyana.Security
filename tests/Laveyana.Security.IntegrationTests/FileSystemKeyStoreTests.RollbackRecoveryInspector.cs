using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Rollback;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.FileSystem.Storage;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

public sealed partial class FileSystemKeyStoreTests
{
    private async Task<(Guid StoreId, byte[] Before, byte[] After, RollbackPreparedWrite Write)>
        NewRecoveryInspectionFixtureAsync()
    {
        FileSystemKeyStore store = await Open();
        (Guid storeId, byte[] before) = await CurrentSnapshotAsync();
        Assert.That((await store.TryCreateAsync(await CreateRequest(KeyId.New(), _name))).Status,
            Is.EqualTo(KeyStoreMutationStatus.Applied));
        byte[] after = (await CurrentSnapshotAsync()).Bytes;
        RollbackPreparedWrite staged = new(Checkpoint(storeId, 1, before), Checkpoint(storeId, 2, after),
            new RollbackRequestId(Guid.NewGuid()), new RollbackRequestId(Guid.NewGuid()), after);
        return (storeId, before, after, staged);
    }

    [Test]
    public async Task RollbackRecoveryInspectorLabelsOldCommittedStateWithoutAuthorizingPrepare()
    {
        var state = await NewRecoveryInspectionFixtureAsync();
        RollbackAuthorityState authority = new(state.Write.Expected);
        Assert.That(RollbackRecoveryInspector.Inspect(state.StoreId, state.Write, state.Before, authority),
            Is.EqualTo(RollbackRecoveryObservation.StagedWithOldCommitObserved));
    }

    [Test]
    public async Task RollbackRecoveryInspectorLabelsPendingIntentWithOldSnapshot()
    {
        var state = await NewRecoveryInspectionFixtureAsync();
        RollbackAuthorityState authority = new(state.Write.Expected, state.Write.Prepared);
        Assert.That(RollbackRecoveryInspector.Inspect(state.StoreId, state.Write, state.Before, authority),
            Is.EqualTo(RollbackRecoveryObservation.PendingWithOldSnapshotObserved));
    }

    [Test]
    public async Task RollbackRecoveryInspectorLabelsPendingIntentWithCandidateWithoutFinalizing()
    {
        var state = await NewRecoveryInspectionFixtureAsync();
        RollbackAuthorityState authority = new(state.Write.Expected, state.Write.Prepared);
        Assert.That(RollbackRecoveryInspector.Inspect(state.StoreId, state.Write, state.After, authority),
            Is.EqualTo(RollbackRecoveryObservation.PendingWithCandidateObserved));
    }

    [Test]
    public async Task RollbackRecoveryInspectorLabelsFinalizedCandidateWithoutCleaningEvidence()
    {
        var state = await NewRecoveryInspectionFixtureAsync();
        RollbackAuthorityState authority = new(state.Write.Prepared);
        Assert.That(RollbackRecoveryInspector.Inspect(state.StoreId, state.Write, state.After, authority),
            Is.EqualTo(RollbackRecoveryObservation.FinalizedWithCandidateObserved));
    }

    [Test]
    public async Task RollbackRecoveryInspectorRejectsActiveRollbackAndUnexpectedPublication()
    {
        var state = await NewRecoveryInspectionFixtureAsync();
        RollbackAuthorityState oldAuthority = new(state.Write.Expected);
        RollbackAuthorityState newAuthority = new(state.Write.Prepared);
        Assert.Multiple(() =>
        {
            Assert.That(RollbackRecoveryInspector.Inspect(state.StoreId, state.Write, state.Before, newAuthority),
                Is.EqualTo(RollbackRecoveryObservation.Blocked));
            Assert.That(RollbackRecoveryInspector.Inspect(state.StoreId, state.Write, state.After, oldAuthority),
                Is.EqualTo(RollbackRecoveryObservation.Blocked));
            Assert.That(RollbackRecoveryInspector.Inspect(state.StoreId, state.Write, [0x01, 0x02], oldAuthority),
                Is.EqualTo(RollbackRecoveryObservation.Blocked));
        });
    }

    [Test]
    public async Task RollbackRecoveryInspectorRejectsMissingForeignOrConflictingAuthorityState()
    {
        var state = await NewRecoveryInspectionFixtureAsync();
        RollbackAuthorityState foreign = new(Checkpoint(Guid.NewGuid(), 1, state.Before));
        RollbackCheckpoint otherPending = Checkpoint(state.StoreId, 2, [0x01, 0x02]);
        RollbackAuthorityState conflict = new(state.Write.Expected, otherPending);
        Assert.Multiple(() =>
        {
            Assert.That(RollbackRecoveryInspector.Inspect(state.StoreId, state.Write, state.Before, null),
                Is.EqualTo(RollbackRecoveryObservation.Blocked));
            Assert.That(RollbackRecoveryInspector.Inspect(state.StoreId, state.Write, state.Before, foreign),
                Is.EqualTo(RollbackRecoveryObservation.Blocked));
            Assert.That(RollbackRecoveryInspector.Inspect(state.StoreId, state.Write, state.After, conflict),
                Is.EqualTo(RollbackRecoveryObservation.Blocked));
            Assert.That(RollbackRecoveryInspector.Inspect(Guid.NewGuid(), state.Write, state.After,
                new RollbackAuthorityState(state.Write.Prepared)),
                Is.EqualTo(RollbackRecoveryObservation.Blocked));
        });
    }

    [Test]
    public async Task RollbackRecoveryInspectorRejectsIndistinguishableOldAndNewBytes()
    {
        var state = await NewRecoveryInspectionFixtureAsync();
        RollbackCheckpoint equalOld = Checkpoint(state.StoreId, 1, state.After);
        RollbackPreparedWrite ambiguous = new(equalOld, state.Write.Prepared,
            state.Write.PrepareRequestId, state.Write.FinalizeRequestId, state.After);
        RollbackAuthorityState authority = new(equalOld, ambiguous.Prepared);
        Assert.That(RollbackRecoveryInspector.Inspect(state.StoreId, ambiguous, state.After, authority),
            Is.EqualTo(RollbackRecoveryObservation.Blocked));
    }

    [Test]
    public async Task RollbackRecoveryInspectorReadsAuthenticatedStageWithoutChangingAnyFiles()
    {
        var state = await NewRecoveryInspectionFixtureAsync();
        (LinuxSecureDirectory? linux, WindowsSecureDirectory? windows) = OpenJournalDirectory();
        using LinuxSecureDirectory? linuxOwner = linux;
        using WindowsSecureDirectory? windowsOwner = windows;
        using FileStream held = (linux is not null
            ? linux.TryAcquireLock(".store.lock", false)
            : windows!.TryAcquireLock(".store.lock", false))
            ?? throw new InvalidOperationException("Store lock unavailable.");

        await RollbackCandidateJournal.StageAsync(linux, windows, _protector, state.Write);
        byte[] snapshotBefore = await File.ReadAllBytesAsync(Path.Combine(_root, "store.lsfs"));
        byte[] candidateBefore = await File.ReadAllBytesAsync(
            Path.Combine(_root, RollbackCandidateJournal.CandidateName));
        byte[] intentBefore = await File.ReadAllBytesAsync(
            Path.Combine(_root, RollbackCandidateJournal.IntentName));
        RollbackPreparedWrite? authenticated = await RollbackCandidateJournal.ReadAsync(
            linux, windows, _protector, state.StoreId);
        Assert.That(authenticated, Is.Not.Null);
        RollbackAuthorityState authority = new(state.Write.Expected, state.Write.Prepared);
        Assert.That(RollbackRecoveryInspector.Inspect(state.StoreId, authenticated!, snapshotBefore, authority),
            Is.EqualTo(RollbackRecoveryObservation.PendingWithCandidateObserved));
        Assert.Multiple(() =>
        {
            Assert.That(File.ReadAllBytes(Path.Combine(_root, "store.lsfs")), Is.EqualTo(snapshotBefore));
            Assert.That(File.ReadAllBytes(Path.Combine(_root, RollbackCandidateJournal.CandidateName)),
                Is.EqualTo(candidateBefore));
            Assert.That(File.ReadAllBytes(Path.Combine(_root, RollbackCandidateJournal.IntentName)),
                Is.EqualTo(intentBefore));
        });
    }
}
