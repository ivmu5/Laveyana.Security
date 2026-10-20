using Laveyana.Security.Abstractions.Rollback;

namespace Laveyana.Security.FileSystem.Storage;

/// <summary>
/// Classifies exact checkpoint combinations without mutating a store or contacting an authority.
/// </summary>
/// <remarks>
/// Caller MUST exclusively lock the pinned store root, authenticate the active snapshot,
/// load the candidate via <see cref="RollbackCandidateJournal.ReadAsync"/>, and obtain a
/// fresh linearizable authority observation. This helper does not check those preconditions.
/// No returned state grants read or write access, resolves a lost RPC response, or establishes
/// durable publication. All cases not explicitly recognized are blocked.
/// </remarks>
internal static class RollbackRecoveryInspector
{
    internal static RollbackRecoveryObservation Inspect(Guid pinnedStoreId, RollbackPreparedWrite staged,
        ReadOnlySpan<byte> activeSnapshot, RollbackAuthorityState? authority)
    {
        if (pinnedStoreId == Guid.Empty)
        {
            throw new ArgumentException("A pinned store identity is required.", nameof(pinnedStoreId));
        }

        ArgumentNullException.ThrowIfNull(staged);

        if (authority is null || staged.Expected.StoreInstanceId != pinnedStoreId ||
            staged.Prepared.StoreInstanceId != pinnedStoreId ||
            authority.Committed.StoreInstanceId != pinnedStoreId ||
            (authority.Pending is not null && authority.Pending.StoreInstanceId != pinnedStoreId))
        {
            return RollbackRecoveryObservation.Blocked;
        }

        byte[] activeDigest = RollbackSnapshotDigest.Compute(pinnedStoreId, activeSnapshot);
        RollbackCheckpoint asOld = new(pinnedStoreId, staged.Expected.Sequence, activeDigest);
        RollbackCheckpoint asNew = new(pinnedStoreId, staged.Prepared.Sequence, activeDigest);
        bool activeOld = staged.Expected.Matches(asOld);
        bool activeNew = staged.Prepared.Matches(asNew);

        // Identical old/new byte commitments cannot identify the publication phase.
        if (activeOld && activeNew)
        {
            return RollbackRecoveryObservation.Blocked;
        }

        if (authority.Pending is not null)
        {
            if (!authority.Committed.Matches(staged.Expected) ||
                !authority.Pending.Matches(staged.Prepared))
            {
                return RollbackRecoveryObservation.Blocked;
            }

            if (activeOld)
            {
                return RollbackRecoveryObservation.PendingWithOldSnapshotObserved;
            }

            return activeNew
                ? RollbackRecoveryObservation.PendingWithCandidateObserved
                : RollbackRecoveryObservation.Blocked;
        }

        if (authority.Committed.Matches(staged.Expected) && activeOld)
        {
            return RollbackRecoveryObservation.StagedWithOldCommitObserved;
        }

        if (authority.Committed.Matches(staged.Prepared) && activeNew)
        {
            return RollbackRecoveryObservation.FinalizedWithCandidateObserved;
        }

        return RollbackRecoveryObservation.Blocked;
    }
}
