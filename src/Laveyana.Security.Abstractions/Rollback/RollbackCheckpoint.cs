using System.Security.Cryptography;

namespace Laveyana.Security.Abstractions.Rollback;

/// <summary>Immutable SHA-256 commitment to one complete persisted store snapshot and authority sequence.</summary>
/// <remarks>
/// Sequence is global to the store, not an individual key revision. The digest is over the
/// exact persisted snapshot bytes, domain-separated by the pinned store UUID. This value
/// does not authenticate the snapshot or establish rollback resistance without a trusted authority.
/// </remarks>
public sealed class RollbackCheckpoint
{
    private readonly byte[] _digest;

    /// <summary>Creates a checkpoint, copying the complete 32-byte SHA-256 digest.</summary>
    public RollbackCheckpoint(Guid storeInstanceId, ulong sequence, ReadOnlySpan<byte> digest)
    {
        if (storeInstanceId == Guid.Empty || sequence == 0)
        {
            throw new ArgumentException("A nonempty store identity and positive authority sequence are required.");
        }

        if (digest.Length != 32)
        {
            throw new ArgumentException("A SHA-256 checkpoint digest must contain exactly 32 bytes.", nameof(digest));
        }

        StoreInstanceId = storeInstanceId;
        Sequence = sequence;
        _digest = digest.ToArray();
    }

    /// <summary>Gets the pinned instance UUID for this store, not a path or provider identifier.</summary>
    public Guid StoreInstanceId { get; }

    /// <summary>Gets the authority-wide positive commit sequence for this store.</summary>
    public ulong Sequence { get; }

    /// <summary>Returns a defensive copy of the checkpoint digest.</summary>
    public byte[] ExportDigestCopy() => (byte[])_digest.Clone();

    /// <summary>Compares both identity and digest without early-exit byte comparisons.</summary>
    public bool Matches(RollbackCheckpoint? other) => other is not null &&
        StoreInstanceId == other.StoreInstanceId && Sequence == other.Sequence &&
        CryptographicOperations.FixedTimeEquals(_digest, other._digest);

    /// <summary>Avoids writing the snapshot digest or store identity to generic logs.</summary>
    public override string ToString() => nameof(RollbackCheckpoint);
}
