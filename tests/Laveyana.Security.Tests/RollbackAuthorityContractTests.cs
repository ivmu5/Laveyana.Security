using System.Text;
using Laveyana.Security.Abstractions.Rollback;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Pure-contract and gate tests; the in-memory authority below is NOT rollback resistant.</summary>
[TestFixture]
internal sealed class RollbackAuthorityContractTests
{
    private static readonly Guid StoreId = Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static readonly Guid OtherStoreId = Guid.Parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    private static readonly byte[] First = Encoding.UTF8.GetBytes("authenticated-snapshot-1");
    private static readonly byte[] Second = Encoding.UTF8.GetBytes("authenticated-snapshot-2");
    private static readonly byte[] Third = Encoding.UTF8.GetBytes("authenticated-snapshot-3");

    private static RollbackCheckpoint Checkpoint(ulong sequence, byte[] bytes, Guid? storeId = null) =>
        new(storeId ?? StoreId, sequence, RollbackSnapshotDigest.Compute(storeId ?? StoreId, bytes));

    [Test]
    public void ContractLivesInAbstractionsAndCannotBeConfusedWithNonceAuthority()
    {
        Assert.That(typeof(IKeyStoreRollbackAuthority).Assembly,
            Is.EqualTo(typeof(Laveyana.Security.Abstractions.Storage.IKeyStore).Assembly));
        Assert.That(typeof(IKeyStoreRollbackAuthority).GetMethod("ReserveAsync"), Is.Null);
        Assert.That(new Laveyana.Security.Abstractions.Storage.KeyStoreCapabilities(false).ProvidesRollbackProtection,
            Is.False);
    }

    [Test]
    public void CheckpointRejectsUndefinedIdentitySequenceAndWrongDigestLength()
    {
        byte[] digest = RollbackSnapshotDigest.Compute(StoreId, First);
        Assert.Throws<ArgumentException>(() => new RollbackCheckpoint(Guid.Empty, 1, digest));
        Assert.Throws<ArgumentException>(() => new RollbackCheckpoint(StoreId, 0, digest));
        Assert.Throws<ArgumentException>(() => new RollbackCheckpoint(StoreId, 1, new byte[31]));
        Assert.Throws<ArgumentException>(() => new RollbackCheckpoint(StoreId, 1, new byte[33]));
        Assert.Throws<ArgumentException>(() => RollbackSnapshotDigest.Compute(Guid.Empty, First));
        Assert.Throws<ArgumentException>(() => RollbackSnapshotGate.Inspect(Guid.Empty, First, null));
    }

    [Test]
    public void DigestBindsExactBytesStoreIdentityAndCommitSequence()
    {
        RollbackCheckpoint first = Checkpoint(1, First);
        Assert.That(first.Matches(Checkpoint(1, First)), Is.True);
        Assert.That(first.Matches(Checkpoint(2, First)), Is.False);
        Assert.That(first.Matches(Checkpoint(1, First, OtherStoreId)), Is.False);
        Assert.That(first.Matches(Checkpoint(1, Second)), Is.False);
        Assert.That(RollbackSnapshotDigest.Compute(StoreId, First),
            Is.Not.EqualTo(RollbackSnapshotDigest.Compute(OtherStoreId, First)));
        Assert.That(first.ToString(), Is.EqualTo(nameof(RollbackCheckpoint)));
        Assert.That(first.ToString(), Does.Not.Contain(StoreId.ToString("D")));
    }

    [Test]
    public void CheckpointOwnsItsDigestAndDoesNotExposeMutableBackingStorage()
    {
        byte[] digest = RollbackSnapshotDigest.Compute(StoreId, First);
        RollbackCheckpoint checkpoint = new(StoreId, 1, digest);
        digest[0] ^= 0xff;
        byte[] exported = checkpoint.ExportDigestCopy();
        exported[0] ^= 0xff;
        Assert.That(checkpoint.Matches(Checkpoint(1, First)), Is.True);
    }

    [Test]
    public void PendingStateRequiresExactNextSequenceAndMatchingIdentity()
    {
        RollbackCheckpoint committed = Checkpoint(1, First);
        Assert.Throws<ArgumentNullException>(() => new RollbackAuthorityState(null!));
        Assert.Throws<ArgumentException>(() => new RollbackAuthorityState(committed, Checkpoint(1, Second)));
        Assert.Throws<ArgumentException>(() => new RollbackAuthorityState(committed, Checkpoint(3, Second)));
        Assert.Throws<ArgumentException>(() => new RollbackAuthorityState(committed, Checkpoint(2, Second, OtherStoreId)));
        Assert.Throws<ArgumentException>(() => new RollbackAuthorityState(Checkpoint(ulong.MaxValue, First),
            Checkpoint(1, Second)));
        Assert.That(new RollbackAuthorityState(committed, Checkpoint(2, Second)).Pending, Is.Not.Null);
    }

    [Test]
    public void ExactCommittedSnapshotIsReadableOnlyWithoutPendingIntent()
    {
        RollbackAuthorityState committed = new(Checkpoint(1, First));
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, First, committed),
            Is.EqualTo(RollbackSnapshotInspection.CommittedMatch));
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, First, null),
            Is.EqualTo(RollbackSnapshotInspection.Rejected));
        Assert.That(RollbackSnapshotGate.Inspect(OtherStoreId, First, committed),
            Is.EqualTo(RollbackSnapshotInspection.Rejected));
    }

    [Test]
    public void OldAuthenticatedSnapshotIsRejectedAfterNewerCheckpointCommitted()
    {
        // Both snapshots are assumed separately authenticated in this scenario.
        RollbackAuthorityState authority = new(Checkpoint(2, Second));
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, Second, authority),
            Is.EqualTo(RollbackSnapshotInspection.CommittedMatch));
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, First, authority),
            Is.EqualTo(RollbackSnapshotInspection.Rejected));
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, Third, authority),
            Is.EqualTo(RollbackSnapshotInspection.Rejected));
    }

    [Test]
    public void PreparedStateRejectsOldFileAndBlocksNewFileUntilFinalized()
    {
        RollbackCheckpoint first = Checkpoint(1, First);
        RollbackCheckpoint second = Checkpoint(2, Second);
        RollbackAuthorityState pending = new(first, second);
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, First, pending),
            Is.EqualTo(RollbackSnapshotInspection.Rejected));
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, Second, pending),
            Is.EqualTo(RollbackSnapshotInspection.RequiresFinalization));
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, Third, pending),
            Is.EqualTo(RollbackSnapshotInspection.Rejected));
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, Second, new RollbackAuthorityState(second)),
            Is.EqualTo(RollbackSnapshotInspection.CommittedMatch));
    }

    [Test]
    public async Task SimulatedProtocolRejectsConflictingPreparesAndHistoricalReplay()
    {
        // Deliberately volatile fake: tests protocol shape only, NOT a trusted authority backend.
        VolatileProtocolFake fake = new();
        RollbackCheckpoint first = Checkpoint(1, First);
        RollbackCheckpoint second = Checkpoint(2, Second);
        RollbackCheckpoint alternative = Checkpoint(2, Third);

        Assert.That(await fake.ReadAsync(StoreId), Is.Null);
        Assert.That(await fake.TryEnrollAsync(first), Is.True);
        Assert.That(await fake.TryEnrollAsync(first), Is.False);
        bool[] races = await Task.WhenAll(
            Task.Run(async () => await fake.TryPrepareAsync(first, second)),
            Task.Run(async () => await fake.TryPrepareAsync(first, alternative)));
        Assert.That(races.Count(item => item), Is.EqualTo(1));

        RollbackAuthorityState pending = (await fake.ReadAsync(StoreId))!;
        Assert.That(pending.Pending, Is.Not.Null);
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, First, pending),
            Is.EqualTo(RollbackSnapshotInspection.Rejected));
        RollbackCheckpoint winner = pending.Pending!;
        Assert.That(await fake.TryFinalizeAsync(first, winner), Is.True);
        Assert.That(await fake.TryFinalizeAsync(first, winner), Is.False);
        RollbackAuthorityState finalizedState = (await fake.ReadAsync(StoreId))!;
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, First, finalizedState),
            Is.EqualTo(RollbackSnapshotInspection.Rejected));
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, winner.Matches(second) ? Second : Third,
            finalizedState), Is.EqualTo(RollbackSnapshotInspection.CommittedMatch));
    }

    [Test]
    public async Task SimulatedCrashAfterPrepareMustRemainUnavailableForReads()
    {
        VolatileProtocolFake fake = new();
        RollbackCheckpoint first = Checkpoint(1, First);
        RollbackCheckpoint second = Checkpoint(2, Second);
        Assert.That(await fake.TryEnrollAsync(first), Is.True);
        Assert.That(await fake.TryPrepareAsync(first, second), Is.True);

        RollbackAuthorityState preparedState = (await fake.ReadAsync(StoreId))!;
        // Simulated loss of response or process before file replacement.
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, First, preparedState),
            Is.EqualTo(RollbackSnapshotInspection.Rejected));
        // Simulated replacement without finalization.
        Assert.That(RollbackSnapshotGate.Inspect(StoreId, Second, preparedState),
            Is.EqualTo(RollbackSnapshotInspection.RequiresFinalization));
    }

    private sealed class VolatileProtocolFake : IKeyStoreRollbackAuthority
    {
        private readonly object _sync = new();
        private readonly Dictionary<Guid, RollbackAuthorityState> _states = new();

        public ValueTask<RollbackAuthorityState?> ReadAsync(Guid storeInstanceId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_sync)
            {
                return ValueTask.FromResult(_states.TryGetValue(storeInstanceId, out RollbackAuthorityState? found)
                    ? found : null);
            }
        }

        public ValueTask<bool> TryEnrollAsync(RollbackCheckpoint initial,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(initial);
            lock (_sync)
            {
                return ValueTask.FromResult(initial.Sequence == 1 &&
                    _states.TryAdd(initial.StoreInstanceId, new RollbackAuthorityState(initial)));
            }
        }

        public ValueTask<bool> TryPrepareAsync(RollbackCheckpoint expected, RollbackCheckpoint next,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(expected);
            ArgumentNullException.ThrowIfNull(next);
            lock (_sync)
            {
                if (!_states.TryGetValue(expected.StoreInstanceId, out RollbackAuthorityState? state) ||
                    state.Pending is not null || !state.Committed.Matches(expected) ||
                    expected.Sequence == ulong.MaxValue || next.StoreInstanceId != expected.StoreInstanceId ||
                    next.Sequence != expected.Sequence + 1)
                {
                    return ValueTask.FromResult(false);
                }

                _states[expected.StoreInstanceId] = new RollbackAuthorityState(expected, next);
                return ValueTask.FromResult(true);
            }
        }

        public ValueTask<bool> TryFinalizeAsync(RollbackCheckpoint expected, RollbackCheckpoint prepared,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(expected);
            ArgumentNullException.ThrowIfNull(prepared);
            lock (_sync)
            {
                if (!_states.TryGetValue(expected.StoreInstanceId, out RollbackAuthorityState? state) ||
                    !state.Committed.Matches(expected) || state.Pending is null ||
                    !state.Pending.Matches(prepared))
                {
                    return ValueTask.FromResult(false);
                }

                _states[expected.StoreInstanceId] = new RollbackAuthorityState(prepared);
                return ValueTask.FromResult(true);
            }
        }
    }
}
