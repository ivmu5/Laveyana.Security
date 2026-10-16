using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Providers;
using Laveyana.Security.Software;

namespace Laveyana.Security.Rotation;

/// <summary>
/// Shared manual and policy-driven rotation execution. This engine neither owns
/// background work nor persists schedule state; backend CAS is always authoritative.
/// </summary>
public sealed class RotationEngine
{
    private readonly ProviderRegistry _registry;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates a manual-only engine unless a host explicitly supplies a worker.</summary>
    public RotationEngine(ProviderRegistry registry, TimeProvider timeProvider)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <summary>Evaluates policy against the injected clock without reading key material.</summary>
    public bool IsDue(RotationAssignment assignment)
    {
        Validate(assignment);
        return _timeProvider.GetUtcNow() >= assignment.DueAtUtc;
    }

    /// <summary>Attempts rotation only if due, fenced by the authoritative active version.</summary>
    public ValueTask<RotationAttemptResult> RotateIfDueAsync(RotationAssignment assignment,
        CancellationToken cancellationToken = default) => ExecuteAsync(assignment, requireDue: true, cancellationToken);

    /// <summary>
    /// Executes an explicitly authorized manual rotation with the identical version fence
    /// but without waiting for a time deadline. Caller remains responsible for authorization.
    /// </summary>
    public ValueTask<RotationAttemptResult> RotateNowAsync(RotationAssignment assignment,
        CancellationToken cancellationToken = default) => ExecuteAsync(assignment, requireDue: false, cancellationToken);

    private async ValueTask<RotationAttemptResult> ExecuteAsync(RotationAssignment assignment,
        bool requireDue, CancellationToken cancellationToken)
    {
        Validate(assignment);
        cancellationToken.ThrowIfCancellationRequested();
        if (requireDue && !IsDue(assignment))
        {
            return new RotationAttemptResult(RotationAttemptStatus.NotDue);
        }

        IKeyProviderBackend backend = _registry.GetRequired(assignment.Handle.ProviderId);
        if (backend is not IConditionalKeyRotationBackend conditional)
        {
            throw new NotSupportedException("Provider does not support atomic version-fenced rotation.");
        }

        KeyDescriptor? snapshot = await backend.FindLogicalAsync(assignment.Handle, cancellationToken)
            .ConfigureAwait(false);
        if (snapshot is null || snapshot.ProviderId != assignment.Handle.ProviderId ||
            snapshot.KeyId != assignment.Handle.KeyId || snapshot.Kind == KeyKind.Unspecified)
        {
            throw new InvalidOperationException("Provider returned missing or inconsistent key metadata.");
        }

        if (snapshot.State != LogicalKeyState.Active ||
            snapshot.ActiveVersion != assignment.ExpectedActiveVersion)
        {
            return new RotationAttemptResult(RotationAttemptStatus.VersionChanged);
        }

        try
        {
            KeyDescriptor committed = await conditional.RotateIfCurrentAsync(assignment.Handle,
                assignment.ExpectedActiveVersion, cancellationToken).ConfigureAwait(false);
            if (committed.ProviderId != assignment.Handle.ProviderId || committed.KeyId != assignment.Handle.KeyId ||
                committed.State != LogicalKeyState.Active || !committed.ActiveVersion.HasValue ||
                committed.ActiveVersion.Value.Value <= assignment.ExpectedActiveVersion.Value)
            {
                throw new InvalidOperationException("Provider returned inconsistent rotation result; reconcile before retrying.");
            }

            return new RotationAttemptResult(RotationAttemptStatus.Rotated, committed);
        }
        catch (SoftwareKeyConflictException)
        {
            return new RotationAttemptResult(RotationAttemptStatus.Conflict);
        }
    }

    private static void Validate(RotationAssignment assignment)
    {
        if (!assignment.Handle.IsDefined || !assignment.ExpectedActiveVersion.IsDefined)
        {
            throw new ArgumentException("A defined rotation assignment is required.", nameof(assignment));
        }

        _ = assignment.DueAtUtc;
    }
}
