using System.Buffers.Binary;
using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Nonce;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Nonce;
using NUnit.Framework;

namespace Laveyana.Security.Tests;

/// <summary>Fail-closed selection and issuance tests; test allocator is NOT a deployable rollback authority.</summary>
[TestFixture]
internal sealed class AeadNoncePolicyTests
{
    private static readonly ProviderId Provider = ProviderId.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly KeyId Key = KeyId.Parse("33333333-3333-4333-8333-333333333333");
    private static readonly KeyReference Reference = new(Provider, Key, new KeyVersion(1));
    private static readonly KeyReference OtherReference = new(Provider, Key, new KeyVersion(2));

    private static AeadNoncePolicyContext Context(
        bool protectedStore = false,
        IRollbackProtectedNonceAllocator? allocator = null,
        AeadKeyOrigin origin = AeadKeyOrigin.FreshlyGenerated,
        AeadRestoreState restore = AeadRestoreState.Clean,
        AeadProviderNonceGuarantee provider = AeadProviderNonceGuarantee.None) =>
        new(Reference, WellKnownAlgorithms.Aes256Gcm, new KeyStoreCapabilities(protectedStore),
            allocator, origin, restore, provider, new AeadNoncePolicyEngine.NonceBudget());

    [Test]
    public void SoftwareDefaultIsRandomizedWithoutIndependentAllocator()
    {
        Assert.That(AeadNoncePolicyEngine.Select(Context()), Is.EqualTo(AeadNonceStrategy.Randomized));
        Assert.That(AeadNoncePolicyEngine.Select(Context(protectedStore: true)),
            Is.EqualTo(AeadNonceStrategy.Randomized));
    }

    [Test]
    public void DeterministicIsDisabledEvenWithBothUnverifiedCapabilities()
    {
        FakeAllocator allocator = new();
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.Select(Context(allocator: allocator)));
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.Select(Context(true, allocator)));
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.Create(Context(true, allocator)));
    }

    [Test]
    public void UnknownImportedHistoryIsNotEligibleForManagedForwardEncryption()
    {
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.Select(
            Context(origin: AeadKeyOrigin.ImportedUnknownNonceHistory)));
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.Select(
            Context(true, new FakeAllocator(), AeadKeyOrigin.ImportedUnknownNonceHistory)));
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.Select(
            Context(origin: AeadKeyOrigin.ImportedUnknownNonceHistory,
                provider: AeadProviderNonceGuarantee.OwnsFreshKeyNonceLifecycle)));
        Assert.That(AeadNoncePolicyEngine.Select(
            Context(origin: AeadKeyOrigin.ImportedUnknownNonceHistory,
                provider: AeadProviderNonceGuarantee.OwnsNonceLifecycleIncludingImportedHistory)),
            Is.EqualTo(AeadNonceStrategy.ProviderManaged));
    }

    [Test]
    public void KnownRestoreCannotResumeUnsafeForwardEncryption()
    {
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.Select(
            Context(restore: AeadRestoreState.KnownRestoredGeneration)));
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.Select(
            Context(true, new FakeAllocator(), restore: AeadRestoreState.KnownRestoredGeneration)));
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.Select(
            Context(restore: AeadRestoreState.KnownRestoredGeneration,
                provider: AeadProviderNonceGuarantee.OwnsNonceLifecycleIncludingImportedHistory)));
    }

    [Test]
    public void InvalidIdentityOrAlgorithmFailsClosed()
    {
        AeadNoncePolicyContext valid = Context();
        Assert.Throws<ArgumentException>(() => AeadNoncePolicyEngine.Select(valid with { Reference = default }));
        Assert.Throws<ArgumentException>(() => AeadNoncePolicyEngine.Select(valid with { Origin = (AeadKeyOrigin)99 }));
        Assert.Throws<ArgumentException>(() => AeadNoncePolicyEngine.Select(valid with { StoreCapabilities = null! }));
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.Select(
            valid with { Algorithm = WellKnownAlgorithms.ChaCha20Poly1305 }));
    }

    [Test]
    public async Task ProviderManagedDoesNotExposeManagedNonce()
    {
        using AeadNonceSession session = AeadNoncePolicyEngine.Create(
            Context(provider: AeadProviderNonceGuarantee.OwnsFreshKeyNonceLifecycle));
        Assert.That(session.Strategy, Is.EqualTo(AeadNonceStrategy.ProviderManaged));
        Assert.ThrowsAsync<InvalidOperationException>(async () => { await session.NextNonceAsync(32); });
    }

    [Test]
    public async Task RandomizedNoncesUseTwelveBytesAndAreDistinctInSample()
    {
        using AeadNonceSession session = AeadNoncePolicyEngine.Create(Context());
        HashSet<string> issued = new(StringComparer.Ordinal);
        for (int i = 0; i < 2048; i++)
        {
            byte[] nonce = await session.NextNonceAsync(1);
            Assert.That(nonce, Has.Length.EqualTo(12));
            Assert.That(issued.Add(Convert.ToHexString(nonce)), Is.True);
        }
    }

    [Test]
    public async Task RandomBudgetFailsClosedWithoutWrapping()
    {
        AeadNoncePolicyEngine.NonceBudget budget =
            new(AeadNoncePolicyEngine.MaxRandomizedInvocationsPerKeyLifetime - 1);
        using AeadNonceSession session = new(OtherReference, AeadNonceStrategy.Randomized, null, budget);
        Assert.That(await session.NextNonceAsync(0), Has.Length.EqualTo(12));
        Assert.ThrowsAsync<CryptographicException>(async () => { await session.NextNonceAsync(0); });
    }

    [Test]
    public void PayloadBoundsAreEnforcedBeforeNonceUse()
    {
        Assert.DoesNotThrow(() => AeadNoncePolicyEngine.ValidatePlaintextLength(0));
        Assert.DoesNotThrow(() => AeadNoncePolicyEngine.ValidatePlaintextLength(
            AeadNoncePolicyEngine.MaxPlaintextBytes));
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.ValidatePlaintextLength(-1));
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.ValidatePlaintextLength(
            AeadNoncePolicyEngine.MaxPlaintextBytes + 1));
    }

    [Test]
    public async Task DeterministicEncodingIsBigEndianAndReusesOnlyReservedRange()
    {
        FakeAllocator authority = new(prefix: 0x11223344, first: 0x0102030405060708);
        using AeadNonceSession session = ModelDeterministicSession(Context(true, authority));
        byte[] first = await session.NextNonceAsync(1);
        Assert.That(Convert.ToHexString(first), Is.EqualTo("112233440102030405060708"));
        for (int i = 1; i < 64; i++)
        {
            await session.NextNonceAsync(1);
        }

        Assert.That(authority.ReservationCount, Is.EqualTo(1));
        byte[] next = await session.NextNonceAsync(1);
        Assert.That(BinaryPrimitives.ReadUInt64BigEndian(next.AsSpan(4)),
            Is.EqualTo(0x0102030405060748UL));
        Assert.That(authority.ReservationCount, Is.EqualTo(2));
    }

    [Test]
    public async Task ParallelCallsToOneSessionCannotRepeatNonces()
    {
        FakeAllocator authority = new();
        using AeadNonceSession session = ModelDeterministicSession(Context(true, authority));
        Task<byte[]>[] tasks = Enumerable.Range(0, 512)
            .Select(_ => Task.Run(async () => await session.NextNonceAsync(4))).ToArray();
        byte[][] values = await Task.WhenAll(tasks);
        Assert.That(values.Select(Convert.ToHexString).Distinct(StringComparer.Ordinal).Count(), Is.EqualTo(512));
        Assert.That(authority.ReservationCount, Is.EqualTo(8));
    }

    [Test]
    public async Task TwoConcurrentSessionsRequireIndependentAuthorityUniqueness()
    {
        FakeAllocator authority = new();
        using AeadNonceSession left = ModelDeterministicSession(Context(true, authority));
        using AeadNonceSession right = ModelDeterministicSession(Context(true, authority));
        Task<byte[]>[] tasks = Enumerable.Range(0, 256)
            .Select(index => Task.Run(async () => await (index % 2 == 0 ? left : right)
                .NextNonceAsync(1))).ToArray();
        byte[][] values = await Task.WhenAll(tasks);
        Assert.That(values.Select(Convert.ToHexString).Distinct(StringComparer.Ordinal).Count(), Is.EqualTo(256));
    }

    [Test]
    public async Task ChangedPrefixIsRejectedBeforeIssuance()
    {
        PrefixChangingAllocator authority = new(Reference);
        using AeadNonceSession session = ModelDeterministicSession(Context(true, authority));
        for (int i = 0; i < 64; i++)
        {
            await session.NextNonceAsync(0);
        }

        Assert.ThrowsAsync<CryptographicException>(async () => { await session.NextNonceAsync(0); });
    }

    [Test]
    public void WrongReservationLengthIsRejected()
    {
        WrongCountAllocator authority = new(Reference);
        using AeadNonceSession session = ModelDeterministicSession(Context(true, authority));
        Assert.ThrowsAsync<CryptographicException>(async () => { await session.NextNonceAsync(0); });
    }

    [Test]
    public void CancellationAfterAuthorityCommitPoisonsSession()
    {
        FakeAllocator authority = new(cancelAfterCommit: true);
        using AeadNonceSession session = ModelDeterministicSession(Context(true, authority));
        Assert.ThrowsAsync<OperationCanceledException>(async () => { await session.NextNonceAsync(0); });
        Assert.ThrowsAsync<CryptographicException>(async () => { await session.NextNonceAsync(0); });
        Assert.That(authority.ReservationCount, Is.EqualTo(1));
    }

    [Test]
    public async Task RestartBurnsUnusedCommittedCountersIfAuthorityPersists()
    {
        FakeAllocator independentAuthority = new();
        byte[] before;
        using (AeadNonceSession oldProcess = ModelDeterministicSession(Context(true, independentAuthority)))
        {
            before = await oldProcess.NextNonceAsync(2);
        }

        // A restored local key-store snapshot is insufficient to roll back an independent authority.
        using AeadNonceSession restarted = ModelDeterministicSession(Context(true, independentAuthority));
        byte[] after = await restarted.NextNonceAsync(2);
        Assert.That(BinaryPrimitives.ReadUInt64BigEndian(after.AsSpan(4)),
            Is.EqualTo(BinaryPrimitives.ReadUInt64BigEndian(before.AsSpan(4)) + 64));
        Assert.That(after, Is.Not.EqualTo(before));
    }

    [Test]
    public async Task DuplicateRangeViolatesContractAndPoisonsSession()
    {
        RepeatingAllocator bad = new(Reference);
        using AeadNonceSession session = ModelDeterministicSession(Context(true, bad));
        for (int i = 0; i < 64; i++)
        {
            await session.NextNonceAsync(0);
        }

        Assert.ThrowsAsync<CryptographicException>(async () => { await session.NextNonceAsync(0); });
        Assert.ThrowsAsync<CryptographicException>(async () => { await session.NextNonceAsync(0); });
    }

    [Test]
    public void WrongKeyReservationIsRejected()
    {
        FakeAllocator wrong = new(overrideReference: OtherReference);
        using AeadNonceSession session = ModelDeterministicSession(Context(true, wrong));
        Assert.ThrowsAsync<CryptographicException>(async () => { await session.NextNonceAsync(0); });
    }

    [Test]
    public void AmbiguousReservationCommitDoesNotAutomaticallyRetry()
    {
        FakeAllocator authority = new(throwAfterCommit: true);
        using AeadNonceSession session = ModelDeterministicSession(Context(true, authority));
        Assert.ThrowsAsync<IOException>(async () => { await session.NextNonceAsync(0); });
        Assert.ThrowsAsync<CryptographicException>(async () => { await session.NextNonceAsync(0); });
        Assert.That(authority.ReservationCount, Is.EqualTo(1));
    }

    [Test]
    public async Task AuthorityExhaustionCannotWrapCounter()
    {
        FakeAllocator nearEnd = new(first: ulong.MaxValue - 64);
        using AeadNonceSession session = ModelDeterministicSession(Context(true, nearEnd));
        for (int i = 0; i < 64; i++)
        {
            await session.NextNonceAsync(0);
        }

        Assert.ThrowsAsync<CryptographicException>(async () => { await session.NextNonceAsync(0); });
    }

    [Test]
    public async Task RestoreInvalidationBlocksExistingRandomAndDeterministicSessions()
    {
        using AeadNonceSession randomized = AeadNoncePolicyEngine.Create(Context());
        using AeadNonceSession deterministic = ModelDeterministicSession(Context(true, new FakeAllocator()));
        Assert.That(await randomized.NextNonceAsync(1), Has.Length.EqualTo(12));
        Assert.That(await deterministic.NextNonceAsync(1), Has.Length.EqualTo(12));
        randomized.InvalidateAfterRestore();
        deterministic.InvalidateAfterRestore();
        Assert.ThrowsAsync<CryptographicException>(async () => { await randomized.NextNonceAsync(1); });
        Assert.ThrowsAsync<CryptographicException>(async () => { await deterministic.NextNonceAsync(1); });
    }

    [Test]
    public void DisposedSessionRejectsFurtherIssuance()
    {
        AeadNonceSession session = AeadNoncePolicyEngine.Create(Context());
        session.Dispose();
        session.Dispose();
        Assert.ThrowsAsync<ObjectDisposedException>(async () => { await session.NextNonceAsync(0); });
    }

    // Model-only issuance tests do not authorize production selection of this strategy.
    private static AeadNonceSession ModelDeterministicSession(AeadNoncePolicyContext context) =>
        new(context.Reference, AeadNonceStrategy.RollbackProtectedDeterministic, context.Allocator, null);

    [Test]
    public void StoredHistoryAndMissingLifetimeBudgetAreRejected()
    {
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.Create(
            Context(origin: AeadKeyOrigin.PersistedUnknownNonceHistory)));
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.Create(
            Context() with { RandomizedBudget = null }));
        Assert.Throws<CryptographicException>(() => AeadNoncePolicyEngine.Create(new(
            Reference, WellKnownAlgorithms.Aes256Gcm, new(false), null)));
    }

    [Test]
    public async Task RandomizedLifetimeBudgetIsSharedAcrossConcurrentSessions()
    {
        AeadNoncePolicyEngine.NonceBudget budget = new(
            AeadNoncePolicyEngine.MaxRandomizedInvocationsPerKeyLifetime - 1);
        AeadNoncePolicyContext context = Context() with { RandomizedBudget = budget };
        using AeadNonceSession first = AeadNoncePolicyEngine.Create(context);
        using AeadNonceSession second = AeadNoncePolicyEngine.Create(context);
        int accepted = 0;
        await Task.WhenAll(Enumerable.Range(0, 32).Select(async i =>
        {
            try
            {
                await (i % 2 == 0 ? first : second).NextNonceAsync(0);
                Interlocked.Increment(ref accepted);
            }
            catch (CryptographicException)
            {
                // Exactly one remaining invocation can succeed across both sessions.
            }
        }));
        Assert.That(accepted, Is.EqualTo(1));
        Assert.ThrowsAsync<CryptographicException>(async () => await first.NextNonceAsync(0));
        Assert.ThrowsAsync<CryptographicException>(async () => await second.NextNonceAsync(0));
    }

    private sealed class FakeAllocator : IRollbackProtectedNonceAllocator
    {
        private readonly object _sync = new();
        private readonly uint _prefix;
        private readonly KeyReference? _overrideReference;
        private readonly bool _throwAfterCommit;
        private readonly bool _cancelAfterCommit;
        private ulong _next;
        private int _reservations;

        internal FakeAllocator(uint prefix = 0x11223344, ulong first = 0,
            KeyReference? overrideReference = null, bool throwAfterCommit = false, bool cancelAfterCommit = false)
        {
            _prefix = prefix;
            _next = first;
            _overrideReference = overrideReference;
            _throwAfterCommit = throwAfterCommit;
            _cancelAfterCommit = cancelAfterCommit;
        }

        internal int ReservationCount => Volatile.Read(ref _reservations);

        public ValueTask<NonceRangeReservation> ReserveAsync(KeyReference reference, uint count,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_sync)
            {
                if (count == 0 || _next > ulong.MaxValue - count)
                {
                    throw new CryptographicException("Counter exhausted.");
                }

                NonceRangeReservation result = new(_overrideReference ?? reference, _prefix, _next, count);
                _next += count;
                _reservations++;
                if (_throwAfterCommit)
                {
                    throw new IOException("Connection failed after durable reservation.");
                }

                if (_cancelAfterCommit)
                {
                    throw new OperationCanceledException("Cancellation after durable commit.");
                }

                return ValueTask.FromResult(result);
            }
        }
    }

    private sealed class WrongCountAllocator(KeyReference reference) : IRollbackProtectedNonceAllocator
    {
        public ValueTask<NonceRangeReservation> ReserveAsync(KeyReference _, uint count,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new NonceRangeReservation(reference, 99, 0, count - 1));
    }

    private sealed class PrefixChangingAllocator(KeyReference reference) : IRollbackProtectedNonceAllocator
    {
        private int _count;

        public ValueTask<NonceRangeReservation> ReserveAsync(KeyReference _, uint count,
            CancellationToken cancellationToken = default)
        {
            int sequence = Interlocked.Increment(ref _count);
            return ValueTask.FromResult(new NonceRangeReservation(reference, (uint)sequence,
                (ulong)(sequence - 1) * count, count));
        }
    }

    private sealed class RepeatingAllocator(KeyReference reference) : IRollbackProtectedNonceAllocator
    {
        public ValueTask<NonceRangeReservation> ReserveAsync(KeyReference _, uint count,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new NonceRangeReservation(reference, 99, 0, count));
    }
}
