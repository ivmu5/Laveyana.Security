namespace Laveyana.Security.Abstractions.Rollback;

/// <summary>OPTIONAL independent authority for detecting restores of older complete key-store snapshots.</summary>
/// <remarks>
/// An implementation MUST reside in a trust domain independent of the protected snapshot and
/// its ordinary filesystem backups; provide rollback-resistant, durable, linearizable CAS
/// across processes; and protect the enrollment, committed checkpoint and pending intent from
/// deletion, recreation, rollback and unauthorized mutation. It MUST NOT infer trust from this
/// interface, an encrypted local file, a TPM presence check or an in-memory counter alone.
///
/// All successful method returns MUST mean the corresponding authority change is durable.
/// Exceptions, timeouts and cancellation around a write may have an ambiguous outcome:
/// callers MUST re-read, reconcile and fail closed until certainty is re-established.
/// A missing state is NOT permission to enroll automatically during an existing store's open.
/// Only an explicitly trusted first-time provisioning flow may enroll sequence 1; the deployment
/// must separately prevent re-enrollment after loss of authority state.
///
/// Expected commit protocol: authenticate the current snapshot; read the authority; require a
/// committed match and no pending intent; durably prepare the next checkpoint; replace and
/// durably flush the snapshot; durably finalize the checkpoint; re-read/verify before serving.
/// A prepared-but-not-finalized state is unavailable for ordinary reads, even if the on-disk
/// bytes match the previously committed checkpoint. Recovery of such states is a separate,
/// audited operation. No caller may assume two independent stores commit atomically.
///
/// This interface is not implemented by FileSystemKeyStore. Its Capabilities flag MUST remain
/// false until a real provider, recovery protocol and adversarial evidence have been reviewed.
/// </remarks>
public interface IKeyStoreRollbackAuthority
{
    /// <summary>Reads an atomic authority record, or null if never provisioned; never creates state.</summary>
    ValueTask<RollbackAuthorityState?> ReadAsync(Guid storeInstanceId,
        CancellationToken cancellationToken = default);

    /// <summary>Atomically enrolls a trusted new store at sequence 1; false if the UUID ever existed.</summary>
    ValueTask<bool> TryEnrollAsync(RollbackCheckpoint initial,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically records the exact successor intent iff committed matches expected and no intent exists.
    /// Returns false without side effects on a definitive conflict.
    /// </summary>
    ValueTask<bool> TryPrepareAsync(RollbackCheckpoint expected, RollbackCheckpoint next,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically promotes a prepared successor iff committed and pending both match the arguments.
    /// Returns false without side effects on a definitive conflict.
    /// </summary>
    ValueTask<bool> TryFinalizeAsync(RollbackCheckpoint expected, RollbackCheckpoint prepared,
        CancellationToken cancellationToken = default);
}
