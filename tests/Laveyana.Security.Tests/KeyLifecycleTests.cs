using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Lifecycle;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Pure, deterministic tests for lifecycle transitions and forbidden state combinations.</summary>
[TestFixture]
internal sealed class KeyLifecycleTests
{
    private static readonly ProviderId Provider = ProviderId.Parse("12345678-1234-4234-8234-123456789abc");
    private static readonly KeyId Key = KeyId.Parse("12345678-1234-4234-8234-123456789abd");
    private static readonly DateTimeOffset Now = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);

    private static KeyVersion V(long value) => new(value);

    private static KeyLifecycleSnapshot New() => KeyLifecyclePlanner.Create(Provider, Key);

    [Test]
    public void CreateHasOneActiveAndOneReservedVersion()
    {
        KeyLifecycleSnapshot snapshot = New();
        Assert.Multiple(() =>
        {
            Assert.That(snapshot.State, Is.EqualTo(LogicalKeyState.Active));
            Assert.That(snapshot.ActiveVersion, Is.EqualTo(V(1)));
            Assert.That(snapshot.HighWaterMark, Is.EqualTo(V(1)));
            Assert.That(snapshot.Versions.Single().State, Is.EqualTo(KeyVersionState.Active));
            Assert.That(snapshot.ToString(), Is.EqualTo("KeyLifecycleSnapshot"));
            Assert.That(snapshot.Versions.Single().ToString(), Is.EqualTo("KeyLifecycleVersion"));
            Assert.That(snapshot.ProviderId, Is.EqualTo(Provider));
            Assert.That(snapshot.KeyId, Is.EqualTo(Key));
        });
        Assert.Throws<ArgumentException>(() => KeyLifecyclePlanner.Create(default, Key));
        Assert.Throws<ArgumentException>(() => KeyLifecyclePlanner.Create(Provider, default));
    }

    [Test]
    public void PendingActivationAtomicallyReplacesActiveAndPreservesOldSnapshot()
    {
        KeyLifecycleSnapshot initial = New();
        KeyLifecycleTransition pending = KeyLifecyclePlanner.CreatePendingVersion(initial);
        KeyLifecycleTransition activated = KeyLifecyclePlanner.Activate(pending.Current, V(2));
        Assert.Multiple(() =>
        {
            Assert.That(pending.AffectedVersion, Is.EqualTo(V(2)));
            Assert.That(pending.HasStateBasedIdempotency, Is.False);
            Assert.That(activated.HasStateBasedIdempotency, Is.True);
            Assert.That(initial.ActiveVersion, Is.EqualTo(V(1)));
            Assert.That(initial.Versions.Count, Is.EqualTo(1));
            Assert.That(pending.Current.Find(V(2))!.State, Is.EqualTo(KeyVersionState.Pending));
            Assert.That(activated.Current.ActiveVersion, Is.EqualTo(V(2)));
            Assert.That(activated.Current.Find(V(1))!.State, Is.EqualTo(KeyVersionState.Retired));
            Assert.That(activated.Current.Find(V(2))!.State, Is.EqualTo(KeyVersionState.Active));
            Assert.That(activated.Current.HighWaterMark, Is.EqualTo(V(2)));
        });

        KeyLifecycleTransition repeat = KeyLifecyclePlanner.Activate(activated.Current, V(2));
        Assert.That(repeat.Disposition, Is.EqualTo(KeyLifecycleDisposition.AlreadyApplied));
        Assert.That(repeat.Current, Is.SameAs(activated.Current));
        Assert.That(Failure(() => KeyLifecyclePlanner.Activate(activated.Current, V(1))),
            Is.EqualTo(KeyLifecycleFailure.InvalidState));
    }

    [Test]
    public void CannotCreateTwoPendingVersionsOrRotateWithUnresolvedPending()
    {
        KeyLifecycleSnapshot snapshot = KeyLifecyclePlanner.CreatePendingVersion(New()).Current;
        Assert.That(Failure(() => KeyLifecyclePlanner.CreatePendingVersion(snapshot)),
            Is.EqualTo(KeyLifecycleFailure.PendingAlreadyExists));
        Assert.That(Failure(() => KeyLifecyclePlanner.Rotate(snapshot)),
            Is.EqualTo(KeyLifecycleFailure.PendingAlreadyExists));
        Assert.That(Failure(() => KeyLifecyclePlanner.RetireKey(snapshot)),
            Is.EqualTo(KeyLifecycleFailure.InvalidState));
        Assert.That(Failure(() => KeyLifecyclePlanner.Activate(snapshot, V(3))),
            Is.EqualTo(KeyLifecycleFailure.VersionNotFound));
        Assert.That(Failure(() => KeyLifecyclePlanner.DiscardPending(snapshot, V(1))),
            Is.EqualTo(KeyLifecycleFailure.InvalidState));
    }

    [Test]
    public void DiscardLeavesPermanentTombstoneAndVersionIsNeverReused()
    {
        KeyLifecycleSnapshot pending = KeyLifecyclePlanner.CreatePendingVersion(New()).Current;
        KeyLifecycleTransition discarded = KeyLifecyclePlanner.DiscardPending(pending, V(2));
        KeyLifecycleTransition next = KeyLifecyclePlanner.CreatePendingVersion(discarded.Current);
        Assert.Multiple(() =>
        {
            Assert.That(discarded.Current.Find(V(2))!.State, Is.EqualTo(KeyVersionState.Deleted));
            Assert.That(next.AffectedVersion, Is.EqualTo(V(3)));
            Assert.That(next.Current.HighWaterMark, Is.EqualTo(V(3)));
            Assert.That(next.Current.Find(V(2))!.State, Is.EqualTo(KeyVersionState.Deleted));
            Assert.That(KeyLifecyclePlanner.DiscardPending(discarded.Current, V(2)).Disposition,
                Is.EqualTo(KeyLifecycleDisposition.AlreadyApplied));
        });
    }

    [Test]
    public void ImmediateRotateRetiresHistoricalAndAllocatesExactlyOneVersion()
    {
        KeyLifecycleTransition rotated = KeyLifecyclePlanner.Rotate(New());
        KeyLifecycleTransition again = KeyLifecyclePlanner.Rotate(rotated.Current);
        Assert.Multiple(() =>
        {
            Assert.That(rotated.Current.ActiveVersion, Is.EqualTo(V(2)));
            Assert.That(rotated.Current.Find(V(1))!.State, Is.EqualTo(KeyVersionState.Retired));
            Assert.That(rotated.HasStateBasedIdempotency, Is.False);
            Assert.That(again.Current.ActiveVersion, Is.EqualTo(V(3)));
            Assert.That(again.Current.HighWaterMark, Is.EqualTo(V(3)));
            Assert.That(rotated.Current.Versions.Count, Is.EqualTo(2));
        });
    }

    [Test]
    public void RetireKeyRequiresNoPendingAndProhibitsReactivation()
    {
        KeyLifecycleTransition retired = KeyLifecyclePlanner.RetireKey(New());
        Assert.Multiple(() =>
        {
            Assert.That(retired.Current.State, Is.EqualTo(LogicalKeyState.Retired));
            Assert.That(retired.Current.ActiveVersion, Is.Null);
            Assert.That(retired.Current.Find(V(1))!.State, Is.EqualTo(KeyVersionState.Retired));
            Assert.That(KeyLifecyclePlanner.RetireKey(retired.Current).Disposition,
                Is.EqualTo(KeyLifecycleDisposition.AlreadyApplied));
        });
        Assert.That(Failure(() => KeyLifecyclePlanner.CreatePendingVersion(retired.Current)),
            Is.EqualTo(KeyLifecycleFailure.InvalidState));
        Assert.That(Failure(() => KeyLifecyclePlanner.Rotate(retired.Current)),
            Is.EqualTo(KeyLifecycleFailure.InvalidState));
        Assert.That(Failure(() => KeyLifecyclePlanner.Activate(retired.Current, V(1))),
            Is.EqualTo(KeyLifecycleFailure.InvalidState));
    }

    [Test]
    public void NormalDeleteRequiresRetiredAndRetainedHistoryIsProtected()
    {
        KeyRetentionConstraint future = new(Now.AddDays(10));
        KeyLifecycleSnapshot initial = KeyLifecyclePlanner.Create(Provider, Key, future);
        Assert.That(Failure(() => KeyLifecyclePlanner.DeleteKey(initial, Now)),
            Is.EqualTo(KeyLifecycleFailure.InvalidState));
        Assert.That(Failure(() => KeyLifecyclePlanner.DeleteVersion(initial, V(1), Now)),
            Is.EqualTo(KeyLifecycleFailure.InvalidState));

        KeyLifecycleSnapshot retired = KeyLifecyclePlanner.RetireKey(initial).Current;
        Assert.That(Failure(() => KeyLifecyclePlanner.DeleteVersion(retired, V(1), Now)),
            Is.EqualTo(KeyLifecycleFailure.RetentionBlocked));
        Assert.That(Failure(() => KeyLifecyclePlanner.DeleteKey(retired, Now)),
            Is.EqualTo(KeyLifecycleFailure.RetentionBlocked));
        KeyLifecycleTransition deleted = KeyLifecyclePlanner.DeleteKey(retired, Now.AddDays(10));
        Assert.Multiple(() =>
        {
            Assert.That(deleted.Current.State, Is.EqualTo(LogicalKeyState.Deleted));
            Assert.That(deleted.Current.Find(V(1))!.State, Is.EqualTo(KeyVersionState.Deleted));
            Assert.That(deleted.Current.HighWaterMark, Is.EqualTo(V(1)));
            Assert.That(KeyLifecyclePlanner.DeleteKey(deleted.Current, Now.AddDays(10)).Disposition,
                Is.EqualTo(KeyLifecycleDisposition.AlreadyApplied));
        });
    }

    [Test]
    public void DeletedVersionRetainsOrdinalAndNormalDeletionIsIdempotent()
    {
        KeyLifecycleSnapshot retired = KeyLifecyclePlanner.RetireKey(New()).Current;
        KeyLifecycleTransition deleted = KeyLifecyclePlanner.DeleteVersion(retired, V(1), Now);
        Assert.That(deleted.Current.State, Is.EqualTo(LogicalKeyState.Retired));
        Assert.That(deleted.Current.Find(V(1))!.State, Is.EqualTo(KeyVersionState.Deleted));
        Assert.That(KeyLifecyclePlanner.DeleteVersion(deleted.Current, V(1), Now).Disposition,
            Is.EqualTo(KeyLifecycleDisposition.AlreadyApplied));
        KeyLifecycleSnapshot final = KeyLifecyclePlanner.DeleteKey(deleted.Current, Now).Current;
        Assert.That(final.State, Is.EqualTo(LogicalKeyState.Deleted));
        Assert.That(final.HighWaterMark, Is.EqualTo(V(1)));
    }

    [Test]
    public void LegalHoldBlocksNormalDeletionButNotExplicitForceKeyDeletion()
    {
        KeyRetentionConstraint held = new(null, isOnHold: true);
        KeyLifecycleSnapshot retired = KeyLifecyclePlanner.RetireKey(
            KeyLifecyclePlanner.Create(Provider, Key, held)).Current;
        Assert.That(Failure(() => KeyLifecyclePlanner.DeleteKey(retired, Now)),
            Is.EqualTo(KeyLifecycleFailure.RetentionBlocked));
        Assert.That(Failure(() => KeyLifecyclePlanner.DeleteVersion(retired, V(1), Now)),
            Is.EqualTo(KeyLifecycleFailure.RetentionBlocked));
        KeyLifecycleTransition forced = KeyLifecyclePlanner.ForceDeleteVersion(retired, V(1));
        Assert.Multiple(() =>
        {
            Assert.That(forced.Current.Find(V(1))!.State, Is.EqualTo(KeyVersionState.Deleted));
            Assert.That(forced.Current.HighWaterMark, Is.EqualTo(V(1)));
            Assert.That(KeyLifecyclePlanner.ForceDeleteVersion(forced.Current, V(1)).Disposition,
                Is.EqualTo(KeyLifecycleDisposition.AlreadyApplied));
        });
        Assert.That(KeyLifecyclePlanner.ForceDeleteKey(retired).Current.State, Is.EqualTo(LogicalKeyState.Deleted));
    }

    [Test]
    public void ForceDeleteVersionCannotOrphanTheCurrentActiveVersion()
    {
        KeyLifecycleSnapshot active = New();
        Assert.That(Failure(() => KeyLifecyclePlanner.ForceDeleteVersion(active, V(1))),
            Is.EqualTo(KeyLifecycleFailure.InvalidState));
        KeyLifecycleSnapshot staged = KeyLifecyclePlanner.CreatePendingVersion(active).Current;
        KeyLifecycleTransition forcedPending = KeyLifecyclePlanner.ForceDeleteVersion(staged, V(2));
        Assert.Multiple(() =>
        {
            Assert.That(forcedPending.Current.State, Is.EqualTo(LogicalKeyState.Active));
            Assert.That(forcedPending.Current.ActiveVersion, Is.EqualTo(V(1)));
            Assert.That(forcedPending.Current.Find(V(2))!.State, Is.EqualTo(KeyVersionState.Deleted));
        });
        Assert.That(Failure(() => KeyLifecyclePlanner.ForceDeleteVersion(forcedPending.Current, V(1))),
            Is.EqualTo(KeyLifecycleFailure.InvalidState));
    }

    [Test]
    public void ForceDeleteKeyIsDestructiveCascadeAndTerminal()
    {
        KeyLifecycleSnapshot withPending = KeyLifecyclePlanner.CreatePendingVersion(New()).Current;
        KeyLifecycleTransition forced = KeyLifecyclePlanner.ForceDeleteKey(withPending);
        Assert.Multiple(() =>
        {
            Assert.That(forced.Current.State, Is.EqualTo(LogicalKeyState.Deleted));
            Assert.That(forced.Current.ActiveVersion, Is.Null);
            Assert.That(forced.Current.Versions.All(entry => entry.State == KeyVersionState.Deleted), Is.True);
            Assert.That(forced.Current.HighWaterMark, Is.EqualTo(V(2)));
            Assert.That(KeyLifecyclePlanner.ForceDeleteKey(forced.Current).Disposition,
                Is.EqualTo(KeyLifecycleDisposition.AlreadyApplied));
        });
        Assert.That(Failure(() => KeyLifecyclePlanner.Rotate(forced.Current)),
            Is.EqualTo(KeyLifecycleFailure.InvalidState));
        Assert.That(Failure(() => KeyLifecyclePlanner.CreatePendingVersion(forced.Current)),
            Is.EqualTo(KeyLifecycleFailure.InvalidState));
        Assert.That(Failure(() => KeyLifecyclePlanner.RetireKey(forced.Current)),
            Is.EqualTo(KeyLifecycleFailure.InvalidState));
    }

    [Test]
    public void InvalidSnapshotsAreRejectedBeforeTheyCanBePlanned()
    {
        KeyLifecycleVersion active = new(V(1), KeyVersionState.Active);
        KeyLifecycleVersion pending = new(V(2), KeyVersionState.Pending);
        Assert.Throws<ArgumentException>(() => new KeyLifecycleSnapshot(
            Provider, Key, LogicalKeyState.Active, V(1), [pending]));
        Assert.Throws<ArgumentException>(() => new KeyLifecycleSnapshot(
            Provider, Key, LogicalKeyState.Active, V(2), [active, active]));
        Assert.Throws<ArgumentException>(() => new KeyLifecycleSnapshot(
            Provider, Key, LogicalKeyState.Active, V(2), [active, new(V(2), KeyVersionState.Active)]));
        Assert.Throws<ArgumentException>(() => new KeyLifecycleSnapshot(
            Provider, Key, LogicalKeyState.Retired, V(2), [active]));
        Assert.Throws<ArgumentException>(() => new KeyLifecycleSnapshot(
            Provider, Key, LogicalKeyState.Retired, V(2), [new(V(1), KeyVersionState.Retired), pending]));
        Assert.Throws<ArgumentException>(() => new KeyLifecycleSnapshot(
            Provider, Key, LogicalKeyState.Deleted, V(2), [new(V(1), KeyVersionState.Retired)]));
        Assert.Throws<ArgumentException>(() => new KeyLifecycleSnapshot(
            Provider, Key, LogicalKeyState.Active, V(1), [active, pending]));
        Assert.Throws<ArgumentException>(() => new KeyLifecycleSnapshot(
            Provider, Key, LogicalKeyState.Active, V(1), []));
        Assert.Throws<ArgumentException>(() => new KeyLifecycleVersion(default, KeyVersionState.Active));
        Assert.Throws<ArgumentException>(() => new KeyLifecycleVersion(V(1), KeyVersionState.Unspecified));
        Assert.That(Failure(() => KeyLifecyclePlanner.DeleteVersion(New(), V(100), Now)),
            Is.EqualTo(KeyLifecycleFailure.VersionNotFound));
    }

    [Test]
    public void ImmutableHistoryDoesNotAliasCallerListOrMutableArray()
    {
        List<KeyLifecycleVersion> supplied = [new(V(1), KeyVersionState.Active)];
        KeyLifecycleSnapshot snapshot = new(Provider, Key, LogicalKeyState.Active, V(1), supplied);
        supplied.Clear();
        Assert.That(snapshot.Versions.Count, Is.EqualTo(1));
        Assert.Throws<NotSupportedException>(() => ((IList<KeyLifecycleVersion>)snapshot.Versions).Clear());
    }

    [Test]
    public void VersionHighWaterMarkSurvivesCompactedTombstonesAndExhaustion()
    {
        KeyLifecycleSnapshot compacted = new(Provider, Key, LogicalKeyState.Active, V(500),
            [new(V(1), KeyVersionState.Active)]);
        KeyLifecycleTransition planned = KeyLifecyclePlanner.CreatePendingVersion(compacted);
        Assert.That(planned.AffectedVersion, Is.EqualTo(V(501)));
        KeyLifecycleSnapshot exhausted = new(Provider, Key, LogicalKeyState.Active,
            new KeyVersion(long.MaxValue), [new(V(1), KeyVersionState.Active)]);
        Assert.That(Failure(() => KeyLifecyclePlanner.Rotate(exhausted)),
            Is.EqualTo(KeyLifecycleFailure.VersionExhausted));
        Assert.That(Failure(() => KeyLifecyclePlanner.CreatePendingVersion(exhausted)),
            Is.EqualTo(KeyLifecycleFailure.VersionExhausted));
    }

    [Test]
    public void DeletionClockMustBeExplicitAndUtc()
    {
        KeyLifecycleSnapshot retired = KeyLifecyclePlanner.RetireKey(New()).Current;
        Assert.Throws<ArgumentException>(() => KeyLifecyclePlanner.DeleteKey(retired, default));
        Assert.Throws<ArgumentException>(() => KeyLifecyclePlanner.DeleteVersion(retired, V(1), Now.ToOffset(TimeSpan.FromHours(3))));
        Assert.Throws<ArgumentException>(() => new KeyRetentionConstraint(Now.ToOffset(TimeSpan.FromHours(1))));
    }

    [Test]
    public void StateBasedIdempotencyNeverAppliesToUnknownCommittedRotations()
    {
        KeyLifecycleSnapshot initial = New();
        KeyLifecycleTransition pending = KeyLifecyclePlanner.CreatePendingVersion(initial);
        KeyLifecycleTransition rotated = KeyLifecyclePlanner.Rotate(initial);
        KeyLifecycleTransition retired = KeyLifecyclePlanner.RetireKey(initial);
        Assert.Multiple(() =>
        {
            Assert.That(pending.HasStateBasedIdempotency, Is.False);
            Assert.That(rotated.HasStateBasedIdempotency, Is.False);
            Assert.That(retired.HasStateBasedIdempotency, Is.True);
            Assert.That(retired.Disposition, Is.EqualTo(KeyLifecycleDisposition.Applied));
            Assert.That(retired.Current, Is.Not.SameAs(initial));
        });
    }

    [Test]
    public void RandomizedSequencesPreserveAllInvariantsAndMonotonicOrdinals()
    {
        Random random = new(20261009);
        for (int run = 0; run < 40; run++)
        {
            KeyLifecycleSnapshot state = New();
            long previousHighWater = state.HighWaterMark.Value;
            for (int step = 0; step < 120; step++)
            {
                try
                {
                    KeyLifecycleTransition candidate = random.Next(9) switch
                    {
                        0 => KeyLifecyclePlanner.CreatePendingVersion(state),
                        1 => KeyLifecyclePlanner.Rotate(state),
                        2 => KeyLifecyclePlanner.RetireKey(state),
                        3 => KeyLifecyclePlanner.ForceDeleteKey(state),
                        4 => KeyLifecyclePlanner.DeleteKey(state, Now),
                        5 => KeyLifecyclePlanner.Activate(state, V(random.Next(1, 20))),
                        6 => KeyLifecyclePlanner.DiscardPending(state, V(random.Next(1, 20))),
                        7 => KeyLifecyclePlanner.DeleteVersion(state, V(random.Next(1, 20)), Now),
                        _ => KeyLifecyclePlanner.ForceDeleteVersion(state, V(random.Next(1, 20))),
                    };
                    state = candidate.Current;
                }
                catch (KeyLifecycleException)
                {
                    // Rejected transitions are expected; the last valid snapshot remains unchanged.
                }

                Assert.Multiple(() =>
                {
                    Assert.That(state.HighWaterMark.Value, Is.GreaterThanOrEqualTo(previousHighWater));
                    Assert.That(state.Versions.Select(v => v.Version).Distinct().Count(), Is.EqualTo(state.Versions.Count));
                    Assert.That(state.Versions.Count(v => v.State == KeyVersionState.Active),
                        Is.EqualTo(state.State == LogicalKeyState.Active ? 1 : 0));
                    Assert.That(state.Versions.Count(v => v.State == KeyVersionState.Pending), Is.LessThanOrEqualTo(1));
                    if (state.State != LogicalKeyState.Active)
                    {
                        Assert.That(state.Versions.Any(v => v.State == KeyVersionState.Pending), Is.False);
                    }
                    if (state.State == LogicalKeyState.Deleted)
                    {
                        Assert.That(state.Versions.All(v => v.State == KeyVersionState.Deleted), Is.True);
                    }
                });
                previousHighWater = state.HighWaterMark.Value;
            }
        }
    }

    private static KeyLifecycleFailure Failure(Action action) =>
        Assert.Throws<KeyLifecycleException>(action)!.Failure;
}
