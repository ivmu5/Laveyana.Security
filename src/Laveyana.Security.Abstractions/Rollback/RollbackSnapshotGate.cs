namespace Laveyana.Security.Abstractions.Rollback;

/// <summary>Fail-closed comparison helper; does not authenticate bytes or provide an external authority.</summary>
public static class RollbackSnapshotGate
{
    /// <summary>
    /// Inspects a fully loaded snapshot against an independently trusted authority observation.
    /// A missing record, foreign identity, or outstanding intent can never grant ordinary read access.
    /// The caller MUST authenticate the actual snapshot before serving data and pin its store UUID.
    /// </summary>
    public static RollbackSnapshotInspection Inspect(Guid expectedStoreInstanceId,
        ReadOnlySpan<byte> persistedSnapshot, RollbackAuthorityState? authority)
    {
        if (expectedStoreInstanceId == Guid.Empty)
        {
            throw new ArgumentException("A pinned store UUID is required.", nameof(expectedStoreInstanceId));
        }

        if (authority is null || authority.Committed.StoreInstanceId != expectedStoreInstanceId)
        {
            return RollbackSnapshotInspection.Rejected;
        }

        byte[] digest = RollbackSnapshotDigest.Compute(expectedStoreInstanceId, persistedSnapshot);
        if (authority.Pending is not null)
        {
            RollbackCheckpoint pendingCandidate = new(expectedStoreInstanceId, authority.Pending.Sequence, digest);
            return pendingCandidate.Matches(authority.Pending)
                ? RollbackSnapshotInspection.RequiresFinalization
                : RollbackSnapshotInspection.Rejected;
        }

        RollbackCheckpoint candidate = new(expectedStoreInstanceId, authority.Committed.Sequence, digest);
        return candidate.Matches(authority.Committed)
            ? RollbackSnapshotInspection.CommittedMatch
            : RollbackSnapshotInspection.Rejected;
    }
}
