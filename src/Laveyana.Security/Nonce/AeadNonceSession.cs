using System.Buffers.Binary;
using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Nonce;

namespace Laveyana.Security.Nonce;

/// <summary>
/// One key-scoped source for managed AES-GCM nonces. The caller must keep the exact key
/// generation, operation authorization and corresponding material aligned at dispatch.
/// </summary>
internal sealed class AeadNonceSession : IDisposable
{
    private const uint RangeSize = 64;
    private readonly KeyReference _reference;
    private readonly IRollbackProtectedNonceAllocator? _allocator;
    private readonly AeadNoncePolicyEngine.NonceBudget? _randomBudget;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private ulong _counter;
    private ulong _endExclusive;
    private uint _prefix;
    private bool _hasDomain;
    private bool _poisoned;
    private int _disposed;
    private int _restoreInvalidated;

    internal AeadNonceSession(KeyReference reference, AeadNonceStrategy strategy,
        IRollbackProtectedNonceAllocator? allocator, AeadNoncePolicyEngine.NonceBudget? randomBudget)
    {
        _reference = reference;
        Strategy = strategy;
        _allocator = allocator;
        _randomBudget = randomBudget;
    }

    internal AeadNonceStrategy Strategy { get; }

    /// <summary>
    /// Issues a new 96-bit nonce for a validated managed operation. Provider-managed AEAD
    /// must execute in its provider and never exposes a locally generated nonce.
    /// </summary>
    internal async ValueTask<byte[]> NextNonceAsync(long plaintextLength, CancellationToken cancellationToken = default)
    {
        AeadNoncePolicyEngine.ValidatePlaintextLength(plaintextLength);
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfUnavailable();

        if (Strategy == AeadNonceStrategy.ProviderManaged)
        {
            throw new InvalidOperationException("Provider-managed AEAD must execute within its verified provider.");
        }

        if (Strategy == AeadNonceStrategy.Randomized)
        {
            _randomBudget!.Consume();
            ThrowIfUnavailable();
            byte[] randomNonce = new byte[12];
            RandomNumberGenerator.Fill(randomNonce);
            return randomNonce;
        }

        // A single key session cannot interleave reservations or dispense a range twice.
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfUnavailable();
            if (_poisoned)
            {
                throw new CryptographicException("Nonce reservation status is uncertain; replace this session after reconciliation.");
            }

            if (_counter == _endExclusive)
            {
                NonceRangeReservation reservation;
                try
                {
                    // A canceled or faulted reservation may still have committed; never retry it here.
                    reservation = await _allocator!.ReserveAsync(_reference, RangeSize, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch
                {
                    _poisoned = true;
                    throw;
                }

                if (reservation.Reference != _reference || reservation.Count != RangeSize ||
                    (_hasDomain && (reservation.Prefix != _prefix || reservation.FirstCounter < _endExclusive)))
                {
                    _poisoned = true;
                    throw new CryptographicException("Allocator violated exact-key nonce domain or range ordering.");
                }

                _prefix = reservation.Prefix;
                _counter = reservation.FirstCounter;
                _endExclusive = reservation.EndExclusive;
                _hasDomain = true;
            }

            ThrowIfUnavailable();
            byte[] nonce = new byte[12];
            BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(0, 4), _prefix);
            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4, 8), _counter);
            _counter++;
            return nonce;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Blocks new issuance immediately after a known restore or key generation invalidation.</summary>
    internal void InvalidateAfterRestore() => Interlocked.Exchange(ref _restoreInvalidated, 1);

    public void Dispose()
    {
        // Mark closed; do not dispose _gate while an asynchronous operation may be waiting.
        Interlocked.Exchange(ref _disposed, 1);
    }

    private void ThrowIfUnavailable()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(AeadNonceSession));
        }

        if (Volatile.Read(ref _restoreInvalidated) != 0)
        {
            throw new CryptographicException("Key generation invalidated by restore; re-key before forward encryption.");
        }
    }
}
