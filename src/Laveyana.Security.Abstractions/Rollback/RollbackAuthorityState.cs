namespace Laveyana.Security.Abstractions.Rollback;

/// <summary>One authoritative committed checkpoint and optionally one pending next commit.</summary>
/// <remarks>
/// An outstanding prepare is NOT a successful commit. No file state is safe to serve while
/// the authority has a pending transition, until independently verified recovery completes.
/// An authority implementation MUST provide a linearizable snapshot of both fields.
/// </remarks>
public sealed class RollbackAuthorityState
{
    /// <summary>Creates a valid single-store committed/pending authority state.</summary>
    public RollbackAuthorityState(RollbackCheckpoint committed, RollbackCheckpoint? pending = null)
    {
        ArgumentNullException.ThrowIfNull(committed);
        if (pending is not null && (pending.StoreInstanceId != committed.StoreInstanceId ||
            committed.Sequence == ulong.MaxValue || pending.Sequence != committed.Sequence + 1))
        {
            throw new ArgumentException("A pending checkpoint must be the exact next sequence of the same store.",
                nameof(pending));
        }

        Committed = committed;
        Pending = pending;
    }

    /// <summary>Gets the last durably finalized checkpoint.</summary>
    public RollbackCheckpoint Committed { get; }

    /// <summary>Gets an intent which has been durably prepared but may not be finalized.</summary>
    public RollbackCheckpoint? Pending { get; }
}
