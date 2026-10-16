using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Lifecycle;

/// <summary>A deterministic transition plan; it must still be committed by an authoritative store.</summary>
internal sealed class KeyLifecycleTransition
{
    public KeyLifecycleTransition(
        KeyLifecycleSnapshot previous,
        KeyLifecycleSnapshot current,
        KeyLifecycleOperation operation,
        KeyLifecycleDisposition disposition,
        KeyVersion? affectedVersion = null)
    {
        Previous = previous;
        Current = current;
        Operation = operation;
        Disposition = disposition;
        AffectedVersion = affectedVersion;
    }

    /// <summary>Gets the input snapshot; not a revision or consistency token.</summary>
    public KeyLifecycleSnapshot Previous { get; }

    /// <summary>Gets the proposed state after the operation.</summary>
    public KeyLifecycleSnapshot Current { get; }

    /// <summary>Gets the operation kind.</summary>
    public KeyLifecycleOperation Operation { get; }

    /// <summary>Gets the repeat/no-op classification of this evaluated state.</summary>
    public KeyLifecycleDisposition Disposition { get; }

    /// <summary>Gets the reserved or affected exact version when relevant.</summary>
    public KeyVersion? AffectedVersion { get; }

    /// <summary>
    /// Indicates the operation has a state-based no-op retry path.
    /// It never authorizes blind retry after an unknown durable commit or revision conflict.
    /// </summary>
    public bool HasStateBasedIdempotency => Operation is not
        (KeyLifecycleOperation.CreatePendingVersion or KeyLifecycleOperation.Rotate);

    /// <summary>Redacts metadata in ordinary logging.</summary>
    public override string ToString() => nameof(KeyLifecycleTransition);
}
