using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Lifecycle;

/// <summary>
/// Plans deterministic, immutable key lifecycle transitions with no I/O, clocks or provider dispatch.
/// Plans are NOT commits: an authoritative backend must check revisions and persist state/material
/// effects atomically, and must never trust stale plans or detached retention metadata.
/// </summary>
internal static class KeyLifecyclePlanner
{
    /// <summary>Creates a new generation with its first Active version, subject to unique identity/name claim.</summary>
    public static KeyLifecycleSnapshot Create(
        ProviderId providerId,
        KeyId keyId,
        KeyRetentionConstraint retention = default) =>
        new(providerId, keyId, LogicalKeyState.Active, new KeyVersion(1),
            [new KeyLifecycleVersion(new KeyVersion(1), KeyVersionState.Active, retention)]);

    /// <summary>Reserves a fresh monotonically increasing Pending ordinal, even if old ones were deleted.</summary>
    public static KeyLifecycleTransition CreatePendingVersion(
        KeyLifecycleSnapshot snapshot,
        KeyRetentionConstraint retention = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        RequireActive(snapshot);
        if (snapshot.Versions.Any(entry => entry.State == KeyVersionState.Pending))
        {
            throw new KeyLifecycleException(KeyLifecycleFailure.PendingAlreadyExists);
        }

        KeyVersion next = ReserveNext(snapshot);
        KeyLifecycleSnapshot result = Next(snapshot, LogicalKeyState.Active, next,
            [.. snapshot.Versions, new KeyLifecycleVersion(next, KeyVersionState.Pending, retention)]);
        return Applied(snapshot, result, KeyLifecycleOperation.CreatePendingVersion, next);
    }

    /// <summary>
    /// Replaces current Active with the specified Pending version in one indivisible domain plan.
    /// Repeating an already successful activation is a no-op only when it is still current Active.
    /// </summary>
    public static KeyLifecycleTransition Activate(KeyLifecycleSnapshot snapshot, KeyVersion version)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        RequireDefined(version);
        KeyLifecycleVersion target = FindRequired(snapshot, version);
        RequireActive(snapshot);
        if (target.State == KeyVersionState.Active && snapshot.ActiveVersion == version)
        {
            return AlreadyApplied(snapshot, KeyLifecycleOperation.Activate, version);
        }

        if (target.State != KeyVersionState.Pending)
        {
            throw new KeyLifecycleException(KeyLifecycleFailure.InvalidState);
        }

        KeyVersion priorActive = snapshot.ActiveVersion!.Value;
        KeyLifecycleVersion[] versions = snapshot.Versions.Select(entry =>
            entry.Version == priorActive ? entry.WithState(KeyVersionState.Retired) :
            entry.Version == version ? entry.WithState(KeyVersionState.Active) : entry).ToArray();
        return Applied(snapshot, Next(snapshot, LogicalKeyState.Active, snapshot.HighWaterMark, versions),
            KeyLifecycleOperation.Activate, version);
    }

    /// <summary>
    /// Reserves and activates a brand-new version atomically in the domain model.
    /// This non-idempotent operation must not be blindly repeated on ambiguous store failures.
    /// </summary>
    public static KeyLifecycleTransition Rotate(
        KeyLifecycleSnapshot snapshot,
        KeyRetentionConstraint retention = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        RequireActive(snapshot);
        if (snapshot.Versions.Any(entry => entry.State == KeyVersionState.Pending))
        {
            throw new KeyLifecycleException(KeyLifecycleFailure.PendingAlreadyExists);
        }

        KeyVersion next = ReserveNext(snapshot);
        KeyVersion priorActive = snapshot.ActiveVersion!.Value;
        KeyLifecycleVersion[] versions =
        [
            .. snapshot.Versions.Select(entry => entry.Version == priorActive
                ? entry.WithState(KeyVersionState.Retired) : entry),
            new KeyLifecycleVersion(next, KeyVersionState.Active, retention),
        ];
        return Applied(snapshot, Next(snapshot, LogicalKeyState.Active, next, versions),
            KeyLifecycleOperation.Rotate, next);
    }

    /// <summary>
    /// Permanently retires a generation and its sole Active version, never reactivating it.
    /// Any Pending version must first be explicitly discarded.
    /// </summary>
    public static KeyLifecycleTransition RetireKey(KeyLifecycleSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (snapshot.State == LogicalKeyState.Retired)
        {
            return AlreadyApplied(snapshot, KeyLifecycleOperation.RetireKey);
        }

        RequireActive(snapshot);
        if (snapshot.Versions.Any(entry => entry.State == KeyVersionState.Pending))
        {
            throw new KeyLifecycleException(KeyLifecycleFailure.InvalidState);
        }

        KeyLifecycleVersion[] versions = snapshot.Versions.Select(entry =>
            entry.State == KeyVersionState.Active ? entry.WithState(KeyVersionState.Retired) : entry).ToArray();
        return Applied(snapshot, Next(snapshot, LogicalKeyState.Retired, snapshot.HighWaterMark, versions),
            KeyLifecycleOperation.RetireKey);
    }

    /// <summary>Discards a never-activated Pending version into a permanent Deleted tombstone.</summary>
    public static KeyLifecycleTransition DiscardPending(KeyLifecycleSnapshot snapshot, KeyVersion version)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        RequireDefined(version);
        KeyLifecycleVersion target = FindRequired(snapshot, version);
        if (target.State == KeyVersionState.Deleted)
        {
            return AlreadyApplied(snapshot, KeyLifecycleOperation.DiscardPending, version);
        }

        if (target.State != KeyVersionState.Pending || snapshot.State != LogicalKeyState.Active)
        {
            throw new KeyLifecycleException(KeyLifecycleFailure.InvalidState);
        }

        return Applied(snapshot, ReplaceState(snapshot, version, KeyVersionState.Deleted),
            KeyLifecycleOperation.DiscardPending, version);
    }

    /// <summary>Normally deletes a Retired version only after its retention constraints are satisfied.</summary>
    public static KeyLifecycleTransition DeleteVersion(
        KeyLifecycleSnapshot snapshot,
        KeyVersion version,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        RequireDefined(version);
        EnsureUtc(nowUtc);
        KeyLifecycleVersion target = FindRequired(snapshot, version);
        if (target.State == KeyVersionState.Deleted)
        {
            return AlreadyApplied(snapshot, KeyLifecycleOperation.DeleteVersion, version);
        }

        if (target.State != KeyVersionState.Retired)
        {
            throw new KeyLifecycleException(KeyLifecycleFailure.InvalidState);
        }

        EnforceRetention(target, nowUtc);
        return Applied(snapshot, ReplaceState(snapshot, version, KeyVersionState.Deleted),
            KeyLifecycleOperation.DeleteVersion, version);
    }

    /// <summary>
    /// Advanced destructive path. Deletes Pending or Retired material without retention checks.
    /// A current Active version can NEVER be individually deleted, even with force.
    /// </summary>
    public static KeyLifecycleTransition ForceDeleteVersion(KeyLifecycleSnapshot snapshot, KeyVersion version)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        RequireDefined(version);
        KeyLifecycleVersion target = FindRequired(snapshot, version);
        if (target.State == KeyVersionState.Deleted)
        {
            return AlreadyApplied(snapshot, KeyLifecycleOperation.ForceDeleteVersion, version);
        }

        if (target.State is not (KeyVersionState.Retired or KeyVersionState.Pending))
        {
            throw new KeyLifecycleException(KeyLifecycleFailure.InvalidState);
        }

        return Applied(snapshot, ReplaceState(snapshot, version, KeyVersionState.Deleted),
            KeyLifecycleOperation.ForceDeleteVersion, version);
    }

    /// <summary>
    /// Normally deletes a Retired generation and all of its remaining historical versions.
    /// The name binding is NOT released by planning; release requires an atomic durable commit.
    /// </summary>
    public static KeyLifecycleTransition DeleteKey(KeyLifecycleSnapshot snapshot, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        EnsureUtc(nowUtc);
        if (snapshot.State == LogicalKeyState.Deleted)
        {
            return AlreadyApplied(snapshot, KeyLifecycleOperation.DeleteKey);
        }

        if (snapshot.State != LogicalKeyState.Retired)
        {
            throw new KeyLifecycleException(KeyLifecycleFailure.InvalidState);
        }

        foreach (KeyLifecycleVersion entry in snapshot.Versions)
        {
            if (entry.State != KeyVersionState.Deleted)
            {
                EnforceRetention(entry, nowUtc);
            }
        }

        return Applied(snapshot, DeleteAll(snapshot), KeyLifecycleOperation.DeleteKey);
    }

    /// <summary>
    /// Advanced destructive cascade. It may destroy the current Active and retained history
    /// together, but never allows an orphaned Active version on an Active logical generation.
    /// </summary>
    public static KeyLifecycleTransition ForceDeleteKey(KeyLifecycleSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (snapshot.State == LogicalKeyState.Deleted)
        {
            return AlreadyApplied(snapshot, KeyLifecycleOperation.ForceDeleteKey);
        }

        return Applied(snapshot, DeleteAll(snapshot), KeyLifecycleOperation.ForceDeleteKey);
    }

    private static KeyLifecycleSnapshot DeleteAll(KeyLifecycleSnapshot snapshot) =>
        Next(snapshot, LogicalKeyState.Deleted, snapshot.HighWaterMark,
            snapshot.Versions.Select(entry => entry.State == KeyVersionState.Deleted
                ? entry : entry.WithState(KeyVersionState.Deleted)));

    private static KeyLifecycleSnapshot ReplaceState(
        KeyLifecycleSnapshot snapshot, KeyVersion version, KeyVersionState state) =>
        Next(snapshot, snapshot.State, snapshot.HighWaterMark,
            snapshot.Versions.Select(entry => entry.Version == version ? entry.WithState(state) : entry));

    private static KeyLifecycleSnapshot Next(
        KeyLifecycleSnapshot snapshot,
        LogicalKeyState state,
        KeyVersion highWaterMark,
        IEnumerable<KeyLifecycleVersion> versions) =>
        new(snapshot.ProviderId, snapshot.KeyId, state, highWaterMark, versions);

    private static KeyLifecycleTransition Applied(
        KeyLifecycleSnapshot before, KeyLifecycleSnapshot after,
        KeyLifecycleOperation operation, KeyVersion? version = null) =>
        new(before, after, operation, KeyLifecycleDisposition.Applied, version);

    private static KeyLifecycleTransition AlreadyApplied(
        KeyLifecycleSnapshot snapshot, KeyLifecycleOperation operation, KeyVersion? version = null) =>
        new(snapshot, snapshot, operation, KeyLifecycleDisposition.AlreadyApplied, version);

    private static KeyLifecycleVersion FindRequired(KeyLifecycleSnapshot snapshot, KeyVersion version) =>
        snapshot.Find(version) ?? throw new KeyLifecycleException(KeyLifecycleFailure.VersionNotFound);

    private static void RequireActive(KeyLifecycleSnapshot snapshot)
    {
        if (snapshot.State != LogicalKeyState.Active)
        {
            throw new KeyLifecycleException(KeyLifecycleFailure.InvalidState);
        }
    }

    private static void RequireDefined(KeyVersion version)
    {
        if (!version.IsDefined)
        {
            throw new ArgumentException("Version must be defined.", nameof(version));
        }
    }

    private static KeyVersion ReserveNext(KeyLifecycleSnapshot snapshot)
    {
        if (snapshot.HighWaterMark.Value == long.MaxValue)
        {
            throw new KeyLifecycleException(KeyLifecycleFailure.VersionExhausted);
        }

        return new KeyVersion(checked(snapshot.HighWaterMark.Value + 1));
    }

    private static void EnsureUtc(DateTimeOffset nowUtc)
    {
        if (nowUtc.Offset != TimeSpan.Zero || nowUtc == default)
        {
            throw new ArgumentException("Deletion time must be a defined UTC instant.", nameof(nowUtc));
        }
    }

    private static void EnforceRetention(KeyLifecycleVersion entry, DateTimeOffset nowUtc)
    {
        if (!entry.Retention.AllowsDeletion(nowUtc))
        {
            throw new KeyLifecycleException(KeyLifecycleFailure.RetentionBlocked);
        }
    }
}
