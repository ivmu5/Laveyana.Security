namespace Laveyana.Security.FileSystem.Storage;

/// <summary>
/// A read-only observation about an authenticated staged candidate and one authority state.
/// </summary>
/// <remarks>
/// No value authorizes a mutation, cleanup, re-enrollment, retry, or serving key material.
/// The observation is not a transaction decision: outstanding RPCs may still complete,
/// namespace power-loss durability is unproven, and a subsequent authority read may differ.
/// </remarks>
internal enum RollbackRecoveryObservation
{
    /// <summary>Missing, foreign, inconsistent, or unexpected data. Fail closed.</summary>
    Blocked = 0,

    /// <summary>
    /// Committed authority and active file match the old checkpoint, without an authority pending intent.
    /// A delayed prepare may still apply: do not infer that the request was never executed.
    /// </summary>
    StagedWithOldCommitObserved = 1,

    /// <summary>
    /// Authority has the exact pending candidate but the active file remains the old checkpoint.
    /// Neither publication nor recovery is authorized by this observation alone.
    /// </summary>
    PendingWithOldSnapshotObserved = 2,

    /// <summary>
    /// Authority has the exact pending candidate and the active file equals its candidate bytes.
    /// Seeing the file does not establish namespace power-loss durability or authorize finalization.
    /// </summary>
    PendingWithCandidateObserved = 3,

    /// <summary>
    /// Authority has finalized the exact candidate and the active file matches it.
    /// Do not remove recovery evidence without a separate verified cleanup protocol.
    /// </summary>
    FinalizedWithCandidateObserved = 4,
}
