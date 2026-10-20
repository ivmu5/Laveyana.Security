namespace Laveyana.Security.Abstractions.Rollback;

/// <summary>Optional request-aware authority contract for resolving lost responses without unsafe retries.</summary>
/// <remarks>
/// This extends <see cref="IKeyStoreRollbackAuthority"/> without breaking its original contract.
/// A protected store requiring automatic reconciliation MUST use only the request-aware mutation
/// overloads, never fall back to the inherited untracked mutation overloads.
/// A conforming provider MUST disable or otherwise prevent the inherited untracked mutations
/// from bypassing its request records for protected stores.
///
/// For each request identity, the provider MUST durably bind the operation kind, store UUID and
/// all exact checkpoint arguments to one immutable decision. Sending the same identity with
/// different arguments MUST fail without side effects. Repeating the same request MUST NOT
/// apply the mutation a second time. True means its durable effect is confirmed; false means
/// a durably terminal no-effect decision for this identity. A transport exception, timeout or
/// cancellation around any write can leave the result ambiguous, including enrollment.
///
/// <see cref="ResolveAsync"/> MUST NOT return <see cref="RollbackRequestResolution.NotApplied"/>
/// based merely on the absence of a record: it must atomically and durably fence that identity
/// against every delayed or retried request, or return Unresolved/throw. A previously applied
/// decision remains queryable even after subsequent commits. An authority must retain its
/// request decisions/fences through failover, backup recovery and process restart for as long
/// as a delayed request or a client recovery intent can remain valid. It must not silently
/// expire these identities based on wall-clock time. This is a provider security obligation,
/// not something an interface or an in-memory fake can prove.
///
/// The caller MUST durably save its request ID, operation kind, checkpoint arguments and exact
/// prepared snapshot before first send. An Unresolved result is never permission to accept
/// an old snapshot or abandon a prepared candidate. Caller cancellation does not undo an RPC.
/// This contract does not provide a server, store staging, remote transport, or rollback safety.
/// </remarks>
public interface IKeyStoreRollbackRequestAuthority : IKeyStoreRollbackAuthority
{
    /// <summary>Request-aware, trusted first enrollment at sequence one.</summary>
    ValueTask<bool> TryEnrollAsync(RollbackRequestId requestId, RollbackCheckpoint initial,
        CancellationToken cancellationToken = default);

    /// <summary>Request-aware durable CAS preparation of the exact next checkpoint.</summary>
    ValueTask<bool> TryPrepareAsync(RollbackRequestId requestId, RollbackCheckpoint expected,
        RollbackCheckpoint next, CancellationToken cancellationToken = default);

    /// <summary>Request-aware durable CAS finalization of an exact prepared checkpoint.</summary>
    ValueTask<bool> TryFinalizeAsync(RollbackRequestId requestId, RollbackCheckpoint expected,
        RollbackCheckpoint prepared, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves one request from independent durable authority state. An unknown ID may return
    /// NotApplied only after a durable fence prevents its later execution. A mismatched store
    /// UUID is an error, not proof of a no-effect result.
    /// </summary>
    ValueTask<RollbackRequestResolution> ResolveAsync(Guid storeInstanceId, RollbackRequestId requestId,
        CancellationToken cancellationToken = default);
}
