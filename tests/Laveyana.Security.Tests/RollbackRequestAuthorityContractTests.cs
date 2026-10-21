using System.Text;
using Laveyana.Security.Abstractions.Rollback;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>
/// Request-resolution contract tests with volatile, locked storage. These DO NOT prove
/// durability, rollback resistance, distributed fencing or filesystem integration.
/// </summary>
[TestFixture]
internal sealed class RollbackRequestAuthorityContractTests
{
    private static readonly Guid Store = Guid.Parse("11111111-2222-4333-8444-555555555555");
    private static readonly Guid AnotherStore = Guid.Parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");

    private static RollbackCheckpoint Checkpoint(ulong sequence, string snapshot, Guid? store = null)
    {
        Guid id = store ?? Store;
        return new RollbackCheckpoint(id, sequence,
            RollbackSnapshotDigest.Compute(id, Encoding.UTF8.GetBytes(snapshot)));
    }

    private static RollbackRequestId Request() => new(Guid.NewGuid());

    [Test]
    public void RequestIdRequiresNonemptyValueAndComparesByIdentity()
    {
        Guid value = Guid.NewGuid();
        Assert.Throws<ArgumentException>(() => new RollbackRequestId(Guid.Empty));
        Assert.That(new RollbackRequestId(value).Equals(new RollbackRequestId(value)), Is.True);
        Assert.That(new RollbackRequestId(value).GetHashCode(),
            Is.EqualTo(new RollbackRequestId(value).GetHashCode()));
        Assert.That(new RollbackRequestId(value).Equals(Request()), Is.False);
        Assert.That(new RollbackRequestId(value).ToString(), Is.EqualTo(nameof(RollbackRequestId)));
        Assert.That((int)RollbackRequestResolution.Unresolved, Is.Zero);
    }

    [Test]
    public async Task DelayedPrepareCannotApplyAfterUnknownRequestWasDurablyFenced()
    {
        VolatileRequestAuthority fake = new();
        RollbackCheckpoint first = Checkpoint(1, "snapshot1");
        RollbackCheckpoint second = Checkpoint(2, "snapshot2");
        Assert.That(await fake.TryEnrollAsync(Request(), first), Is.True);

        RollbackRequestId delayed = Request();
        // Simulate a sent RPC stalled in the network BEFORE reaching the authority.
        // Read still shows the original checkpoint: this is NOT proof the RPC has stopped.
        Assert.That((await fake.ReadAsync(Store))!.Committed.Matches(first), Is.True);
        Assert.That(await fake.ResolveAsync(Store, delayed), Is.EqualTo(RollbackRequestResolution.NotApplied));

        // The delayed message finally arrives. The durable fence must win.
        Assert.That(await fake.TryPrepareAsync(delayed, first, second), Is.False);
        Assert.That((await fake.ReadAsync(Store))!.Pending, Is.Null);
        Assert.That(await fake.ResolveAsync(Store, delayed), Is.EqualTo(RollbackRequestResolution.NotApplied));
    }

    [Test]
    public async Task UnknownRequestIsUnresolvedWhenAuthorityCannotFenceIt()
    {
        VolatileRequestAuthority fake = new() { CanFenceUnknown = false };
        RollbackCheckpoint first = Checkpoint(1, "snapshot1");
        RollbackCheckpoint second = Checkpoint(2, "snapshot2");
        RollbackRequestId delayed = Request();
        Assert.That(await fake.TryEnrollAsync(Request(), first), Is.True);

        // No terminal decision; a later prepare can still succeed.
        Assert.That(await fake.ResolveAsync(Store, delayed), Is.EqualTo(RollbackRequestResolution.Unresolved));
        Assert.That(await fake.TryPrepareAsync(delayed, first, second), Is.True);
        Assert.That(await fake.ResolveAsync(Store, delayed), Is.EqualTo(RollbackRequestResolution.Applied));
        Assert.That((await fake.ReadAsync(Store))!.Pending!.Matches(second), Is.True);
    }

    [Test]
    public async Task LostPrepareReplyIsResolvedFromTheOriginalRequestWithoutAnotherMutation()
    {
        VolatileRequestAuthority fake = new();
        RollbackCheckpoint first = Checkpoint(1, "snapshot1");
        RollbackCheckpoint second = Checkpoint(2, "snapshot2");
        RollbackRequestId request = Request();
        Assert.That(await fake.TryEnrollAsync(Request(), first), Is.True);
        _ = await fake.TryPrepareAsync(request, first, second); // Client loses the reply.

        Assert.That(await fake.ResolveAsync(Store, request), Is.EqualTo(RollbackRequestResolution.Applied));
        Assert.That(await fake.TryPrepareAsync(request, first, second), Is.True); // Same request, no new effect.
        Assert.That((await fake.ReadAsync(Store))!.Pending!.Matches(second), Is.True);
        RollbackAuthorityState? state = await fake.ReadAsync(Store);
        byte[] oldSnapshotBytes = Encoding.UTF8.GetBytes("snapshot1");
        Assert.That(RollbackSnapshotGate.Inspect(Store, oldSnapshotBytes, state),
            Is.EqualTo(RollbackSnapshotInspection.Rejected));
    }

    [Test]
    public async Task FinalizationResolutionRemainsAppliedAfterTheStoreAdvances()
    {
        VolatileRequestAuthority fake = new();
        RollbackCheckpoint first = Checkpoint(1, "snapshot1");
        RollbackCheckpoint second = Checkpoint(2, "snapshot2");
        RollbackCheckpoint third = Checkpoint(3, "snapshot3");
        RollbackRequestId finalization = Request();
        Assert.That(await fake.TryEnrollAsync(Request(), first), Is.True);
        Assert.That(await fake.TryPrepareAsync(Request(), first, second), Is.True);
        _ = await fake.TryFinalizeAsync(finalization, first, second); // Lost response.
        Assert.That(await fake.TryPrepareAsync(Request(), second, third), Is.True);
        Assert.That(await fake.TryFinalizeAsync(Request(), second, third), Is.True);

        // Current committed state is third, but the old finalization request is still known.
        Assert.That(await fake.ResolveAsync(Store, finalization), Is.EqualTo(RollbackRequestResolution.Applied));
        Assert.That(await fake.TryFinalizeAsync(finalization, first, second), Is.True);
        Assert.That((await fake.ReadAsync(Store))!.Committed.Matches(third), Is.True);
    }

    [Test]
    public async Task ConflictIsTerminalAndTheSameIdCannotMutateAfterStateChanges()
    {
        VolatileRequestAuthority fake = new();
        RollbackCheckpoint first = Checkpoint(1, "snapshot1");
        RollbackCheckpoint second = Checkpoint(2, "snapshot2");
        RollbackRequestId conflict = Request();
        Assert.That(await fake.TryEnrollAsync(Request(), first), Is.True);
        Assert.That(await fake.TryPrepareAsync(conflict, Checkpoint(1, "wrong"), second), Is.False);
        Assert.That(await fake.ResolveAsync(Store, conflict), Is.EqualTo(RollbackRequestResolution.NotApplied));
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            _ = await fake.TryPrepareAsync(conflict, first, second);
        });
        Assert.That((await fake.ReadAsync(Store))!.Pending, Is.Null);
    }

    [Test]
    public async Task IdentityCannotBeReusedForOtherOperationOrStore()
    {
        VolatileRequestAuthority fake = new();
        RollbackCheckpoint first = Checkpoint(1, "snapshot1");
        RollbackCheckpoint second = Checkpoint(2, "snapshot2");
        RollbackRequestId enroll = Request();
        Assert.That(await fake.TryEnrollAsync(enroll, first), Is.True);
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            _ = await fake.TryPrepareAsync(enroll, first, second);
        });
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            _ = await fake.ResolveAsync(AnotherStore, enroll);
        });
        Assert.That(await fake.ResolveAsync(Store, enroll), Is.EqualTo(RollbackRequestResolution.Applied));
    }

    [Test]
    public async Task DelayedEnrollmentIsRejectedAfterResolutionFence()
    {
        VolatileRequestAuthority fake = new();
        RollbackRequestId delayed = Request();
        RollbackCheckpoint first = Checkpoint(1, "snapshot1");
        Assert.That(await fake.ResolveAsync(Store, delayed), Is.EqualTo(RollbackRequestResolution.NotApplied));
        Assert.That(await fake.TryEnrollAsync(delayed, first), Is.False);
        Assert.That(await fake.ReadAsync(Store), Is.Null);
    }

    [Test]
    public async Task DelayedFinalizeCannotAdvanceAfterRequestWasFenced()
    {
        VolatileRequestAuthority fake = new();
        RollbackCheckpoint first = Checkpoint(1, "snapshot1");
        RollbackCheckpoint second = Checkpoint(2, "snapshot2");
        Assert.That(await fake.TryEnrollAsync(Request(), first), Is.True);
        Assert.That(await fake.TryPrepareAsync(Request(), first, second), Is.True);
        RollbackRequestId delayed = Request();

        Assert.That(await fake.ResolveAsync(Store, delayed), Is.EqualTo(RollbackRequestResolution.NotApplied));
        Assert.That(await fake.TryFinalizeAsync(delayed, first, second), Is.False);
        RollbackAuthorityState state = (await fake.ReadAsync(Store))!;
        Assert.That(state.Committed.Matches(first), Is.True);
        Assert.That(state.Pending!.Matches(second), Is.True);
    }

    [Test]
    public async Task ConcurrentDuplicatePrepareRequestsShareExactlyOneDecision()
    {
        VolatileRequestAuthority fake = new();
        RollbackCheckpoint first = Checkpoint(1, "snapshot1");
        RollbackCheckpoint second = Checkpoint(2, "snapshot2");
        RollbackRequestId shared = Request();
        Assert.That(await fake.TryEnrollAsync(Request(), first), Is.True);

        bool[] results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            Task.Run(async () => await fake.TryPrepareAsync(shared, first, second))));
        Assert.That(results, Is.All.True);
        Assert.That(await fake.ResolveAsync(Store, shared), Is.EqualTo(RollbackRequestResolution.Applied));
        Assert.That((await fake.ReadAsync(Store))!.Pending!.Matches(second), Is.True);
    }

    [Test]
    public async Task UntrackedMutationMethodsCannotBypassRequestRecordsInThisFake()
    {
        VolatileRequestAuthority fake = new();
        RollbackCheckpoint first = Checkpoint(1, "snapshot1");
        RollbackCheckpoint second = Checkpoint(2, "snapshot2");
        Assert.ThrowsAsync<NotSupportedException>(async () =>
        {
            _ = await fake.TryEnrollAsync(first);
        });
        Assert.ThrowsAsync<NotSupportedException>(async () =>
        {
            _ = await fake.TryPrepareAsync(first, second);
        });
        Assert.ThrowsAsync<NotSupportedException>(async () =>
        {
            _ = await fake.TryFinalizeAsync(first, second);
        });
        Assert.That(await fake.ReadAsync(Store), Is.Null);
    }

    [Test]
    public async Task SimulatedRestartPreservesAppliedDecisionsAndFences()
    {
        VolatileRequestAuthority authority = new();
        RollbackCheckpoint first = Checkpoint(1, "restart-first");
        RollbackCheckpoint second = Checkpoint(2, "restart-second");
        RollbackRequestId enroll = Request();
        RollbackRequestId prepare = Request();
        RollbackRequestId delayed = Request();
        Assert.That(await authority.TryEnrollAsync(enroll, first), Is.True);
        Assert.That(await authority.TryPrepareAsync(prepare, first, second), Is.True);
        Assert.That(await authority.ResolveAsync(Store, delayed), Is.EqualTo(RollbackRequestResolution.NotApplied));

        // Copy the fake's complete conceptual database, including decision tombstones.
        // This is a logical restart simulation, not disk or provider durability evidence.
        VolatileRequestAuthority restarted = authority.CopyForRestart();
        Assert.That(await restarted.ResolveAsync(Store, enroll), Is.EqualTo(RollbackRequestResolution.Applied));
        Assert.That(await restarted.ResolveAsync(Store, prepare), Is.EqualTo(RollbackRequestResolution.Applied));
        Assert.That(await restarted.TryPrepareAsync(prepare, first, second), Is.True);
        Assert.That(await restarted.TryFinalizeAsync(delayed, first, second), Is.False);
        Assert.That((await restarted.ReadAsync(Store))!.Pending!.Matches(second), Is.True);
        Assert.That(await restarted.TryFinalizeAsync(Request(), first, second), Is.True);
        Assert.That(await restarted.CopyForRestart().ResolveAsync(Store, prepare), Is.EqualTo(RollbackRequestResolution.Applied));
    }

    [Test]
    public async Task SimulatedOldAuthorityDatabaseCannotServeOrReenrollBehindIndependentAnchor()
    {
        VolatileRequestAuthority authority = new();
        RollbackCheckpoint first = Checkpoint(1, "backup-first");
        RollbackCheckpoint second = Checkpoint(2, "backup-second");
        await authority.TryEnrollAsync(Request(), first);
        VolatileRequestAuthority oldBackup = authority.CopyForRestart();
        await authority.TryPrepareAsync(Request(), first, second);
        await authority.TryFinalizeAsync(Request(), first, second);
        VolatileRequestAuthority restored = authority.RestoreOldDatabaseForTest(oldBackup);
        Assert.ThrowsAsync<IOException>(async () => await restored.ReadAsync(Store));
        Assert.ThrowsAsync<IOException>(async () => await restored.ResolveAsync(Store, Request()));
        Assert.ThrowsAsync<IOException>(async () => await restored.TryEnrollAsync(Request(), first));
        Assert.ThrowsAsync<IOException>(async () => await restored.TryPrepareAsync(Request(), first, second));
    }

    private sealed class VolatileRequestAuthority : IKeyStoreRollbackRequestAuthority
    {
        private readonly object _sync = new();
        private readonly Dictionary<Guid, RollbackAuthorityState> _stores = new();
        private readonly Dictionary<Guid, RequestRecord> _requests = new();

        public bool CanFenceUnknown { get; init; } = true;
        private int _independentlyAnchoredRequestCount;

        internal VolatileRequestAuthority CopyForRestart()
        {
            lock (_sync)
            {
                RequireModelAnchor();
                VolatileRequestAuthority copy = new() { CanFenceUnknown = CanFenceUnknown };
                foreach (var pair in _stores)
                {
                    copy._stores.Add(pair.Key, pair.Value);
                }

                foreach (var pair in _requests)
                {
                    copy._requests.Add(pair.Key, pair.Value);
                }

                copy._independentlyAnchoredRequestCount = _independentlyAnchoredRequestCount;
                return copy;
            }
        }

        internal VolatileRequestAuthority RestoreOldDatabaseForTest(VolatileRequestAuthority backup)
        {
            VolatileRequestAuthority restored = backup.CopyForRestart();
            // Model an anchor OUTSIDE the rolled-back database; never claim this
            // in-memory count establishes such an anchor for a real authority.
            restored._independentlyAnchoredRequestCount = _independentlyAnchoredRequestCount;
            return restored;
        }

        private void RequireModelAnchor()
        {
            if (_requests.Count != _independentlyAnchoredRequestCount)
            {
                throw new IOException("Simulated authority database rollback: independent anchor mismatch.");
            }
        }

        public ValueTask<RollbackAuthorityState?> ReadAsync(Guid storeInstanceId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_sync)
            {
                RequireModelAnchor();
                return ValueTask.FromResult(_stores.GetValueOrDefault(storeInstanceId));
            }
        }

        // The inherited mutation signatures MUST NOT bypass request-record protection.
        public ValueTask<bool> TryEnrollAsync(RollbackCheckpoint initial,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("Untracked authority mutations are disabled.");

        public ValueTask<bool> TryPrepareAsync(RollbackCheckpoint expected, RollbackCheckpoint next,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("Untracked authority mutations are disabled.");

        public ValueTask<bool> TryFinalizeAsync(RollbackCheckpoint expected, RollbackCheckpoint prepared,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("Untracked authority mutations are disabled.");

        public ValueTask<bool> TryEnrollAsync(RollbackRequestId requestId, RollbackCheckpoint initial,
            CancellationToken cancellationToken = default) => Apply(requestId, "enroll", null, initial,
                () => initial.Sequence == 1 && _stores.TryAdd(initial.StoreInstanceId,
                    new RollbackAuthorityState(initial)), cancellationToken);

        public ValueTask<bool> TryPrepareAsync(RollbackRequestId requestId, RollbackCheckpoint expected,
            RollbackCheckpoint next, CancellationToken cancellationToken = default) =>
            Apply(requestId, "prepare", expected, next, () =>
            {
                if (!_stores.TryGetValue(expected.StoreInstanceId, out RollbackAuthorityState? state) ||
                    state.Pending is not null || !state.Committed.Matches(expected) ||
                    expected.Sequence == ulong.MaxValue || next.StoreInstanceId != expected.StoreInstanceId ||
                    next.Sequence != expected.Sequence + 1)
                {
                    return false;
                }

                _stores[expected.StoreInstanceId] = new RollbackAuthorityState(expected, next);
                return true;
            }, cancellationToken);

        public ValueTask<bool> TryFinalizeAsync(RollbackRequestId requestId, RollbackCheckpoint expected,
            RollbackCheckpoint prepared, CancellationToken cancellationToken = default) =>
            Apply(requestId, "finalize", expected, prepared, () =>
            {
                if (!_stores.TryGetValue(expected.StoreInstanceId, out RollbackAuthorityState? state) ||
                    !state.Committed.Matches(expected) || state.Pending is null ||
                    !state.Pending.Matches(prepared))
                {
                    return false;
                }

                _stores[expected.StoreInstanceId] = new RollbackAuthorityState(prepared);
                return true;
            }, cancellationToken);

        public ValueTask<RollbackRequestResolution> ResolveAsync(Guid storeInstanceId,
            RollbackRequestId requestId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(requestId);
            if (storeInstanceId == Guid.Empty)
            {
                throw new ArgumentException("Store identity cannot be empty.", nameof(storeInstanceId));
            }

            lock (_sync)
            {
                RequireModelAnchor();
                if (_requests.TryGetValue(requestId.Value, out RequestRecord? found))
                {
                    if (found.StoreInstanceId != storeInstanceId)
                    {
                        throw new InvalidOperationException("Request belongs to another store.");
                    }

                    return ValueTask.FromResult(found.Resolution);
                }

                if (!CanFenceUnknown)
                {
                    return ValueTask.FromResult(RollbackRequestResolution.Unresolved);
                }

                // This is in-memory ONLY. A real provider MUST persist this tombstone durably.
                _requests[requestId.Value] = new RequestRecord(storeInstanceId, "fenced", null,
                    null, RollbackRequestResolution.NotApplied);
                _independentlyAnchoredRequestCount = _requests.Count;
                return ValueTask.FromResult(RollbackRequestResolution.NotApplied);
            }
        }

        private ValueTask<bool> Apply(RollbackRequestId requestId, string kind,
            RollbackCheckpoint? expected, RollbackCheckpoint next, Func<bool> apply,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(requestId);
            ArgumentNullException.ThrowIfNull(next);
            lock (_sync)
            {
                RequireModelAnchor();
                if (_requests.TryGetValue(requestId.Value, out RequestRecord? recorded))
                {
                    if (recorded.StoreInstanceId != next.StoreInstanceId)
                    {
                        throw new InvalidOperationException("Request belongs to another store.");
                    }

                    if (recorded.Kind == "fenced")
                    {
                        return ValueTask.FromResult(false);
                    }

                    if (recorded.Kind != kind || !Same(recorded.Expected, expected) ||
                        !Same(recorded.Next, next))
                    {
                        throw new InvalidOperationException("Request ID was reused with different arguments.");
                    }

                    return ValueTask.FromResult(recorded.Resolution == RollbackRequestResolution.Applied);
                }

                bool result = apply();
                _requests.Add(requestId.Value, new RequestRecord(next.StoreInstanceId, kind,
                    expected, next, result ? RollbackRequestResolution.Applied :
                        RollbackRequestResolution.NotApplied));
                _independentlyAnchoredRequestCount = _requests.Count;
                return ValueTask.FromResult(result);
            }
        }

        private static bool Same(RollbackCheckpoint? a, RollbackCheckpoint? b) =>
            a is null ? b is null : a.Matches(b);

        private sealed record RequestRecord(Guid StoreInstanceId, string Kind,
            RollbackCheckpoint? Expected, RollbackCheckpoint? Next,
            RollbackRequestResolution Resolution);
    }
}
