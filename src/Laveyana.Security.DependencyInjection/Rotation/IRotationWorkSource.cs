using Laveyana.Security.Rotation;

namespace Laveyana.Security.DependencyInjection.Rotation;

/// <summary>
/// Application-owned durable work source. ClaimNextAsync MUST atomically and durably
/// mark a DUE schedule assignment claimed BEFORE returning it; a claimed assignment
/// MUST NEVER be delivered again automatically, even after process failure.
/// Reconciliation of incomplete claims and scheduling the next expected version
/// are explicit application responsibilities. An in-memory queue is not suitable
/// for cross-process production rotation.
/// </summary>
public interface IRotationWorkSource
{
    /// <summary>
    /// Atomically claims at most one due assignment, or returns null otherwise.
    /// The source MUST NOT claim future work; the worker faults if it receives any.
    /// </summary>
    ValueTask<RotationAssignment?> ClaimNextAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists an unambiguous outcome. If this operation fails, the claim remains
    /// blocked for reconciliation; the worker must not retry the rotation.
    /// </summary>
    ValueTask RecordResultAsync(RotationAssignment assignment, RotationAttemptResult result,
        CancellationToken cancellationToken = default);
}
