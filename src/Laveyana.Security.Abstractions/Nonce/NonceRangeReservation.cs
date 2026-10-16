using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Nonce;

/// <summary>Unique committed range in a 32-bit-prefix/64-bit-counter deterministic nonce domain.</summary>
/// <remarks>For 96-bit nonces, encode Prefix in big-endian 4 bytes and counter in big-endian 8 bytes.</remarks>
public readonly record struct NonceRangeReservation
{
    /// <summary>Creates a valid reservation; the exclusive end must fit in UInt64.</summary>
    public NonceRangeReservation(KeyReference reference, uint prefix, ulong firstCounter, uint count)
    {
        if (!reference.IsDefined || count == 0 || firstCounter > ulong.MaxValue - count)
        {
            throw new ArgumentException("Reservation identity, count or counter range is invalid.");
        }

        Reference = reference;
        Prefix = prefix;
        FirstCounter = firstCounter;
        Count = count;
    }

    /// <summary>Gets the exact key version bound to this reservation.</summary>
    public KeyReference Reference { get; }

    /// <summary>Gets the persistently bound nonce domain prefix.</summary>
    public uint Prefix { get; }

    /// <summary>Gets the inclusive first counter in the reserved range.</summary>
    public ulong FirstCounter { get; }

    /// <summary>Gets the number of counters reserved.</summary>
    public uint Count { get; }

    /// <summary>Gets the exclusive end of the range.</summary>
    public ulong EndExclusive => checked(FirstCounter + Count);
}
