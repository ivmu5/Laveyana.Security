namespace Laveyana.Security.Abstractions.Rollback;

/// <summary>The conservative outcome of comparing a snapshot with external authority state.</summary>
public enum RollbackSnapshotInspection
{
    /// <summary>Missing, mismatched, older, or ambiguous state; never serve the snapshot.</summary>
    Rejected = 0,

    /// <summary>Exact committed match, with no outstanding intent; other authentication checks still apply.</summary>
    CommittedMatch = 1,

    /// <summary>Matches a pending intent; NOT readable until trusted finalization and re-validation.</summary>
    RequiresFinalization = 2,
}
