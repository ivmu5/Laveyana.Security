using System.Security.Cryptography;
using System.Text;
using Laveyana.Security.Abstractions.Rollback;

namespace Laveyana.Security.FileSystem.Storage;

/// <summary>Internal, immutable description of one not-yet-submitted rollback prepare/finalize pair.</summary>
/// <remarks>
/// This record is not a trusted authority decision. Its serialized representation is authenticated
/// separately by the root protector before being accepted from the filesystem.
/// </remarks>
internal sealed class RollbackPreparedWrite
{
    private const int RecordLength = 4 + 2 + 2 + 16 + 8 + 32 + 8 + 32 + 16 + 16 + 4;
    private readonly byte[] _snapshot;

    internal RollbackPreparedWrite(RollbackCheckpoint expected, RollbackCheckpoint prepared,
        RollbackRequestId prepareRequestId, RollbackRequestId finalizeRequestId, byte[] candidateSnapshot)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(prepareRequestId);
        ArgumentNullException.ThrowIfNull(finalizeRequestId);
        ArgumentNullException.ThrowIfNull(candidateSnapshot);

        if (expected.StoreInstanceId != prepared.StoreInstanceId ||
            expected.Sequence == ulong.MaxValue || prepared.Sequence != expected.Sequence + 1 ||
            prepareRequestId.Equals(finalizeRequestId) ||
            candidateSnapshot.Length is < 24 or > FileSystemSnapshotCodec.MaximumBodyLength + 65536 + 256)
        {
            throw new ArgumentException("Invalid rollback staging transition or snapshot size.");
        }

        byte[] actualDigest = RollbackSnapshotDigest.Compute(prepared.StoreInstanceId, candidateSnapshot);
        if (!CryptographicOperations.FixedTimeEquals(actualDigest, prepared.ExportDigestCopy()))
        {
            throw new ArgumentException("The prepared checkpoint does not bind the exact candidate snapshot.",
                nameof(candidateSnapshot));
        }

        Expected = expected;
        Prepared = prepared;
        PrepareRequestId = prepareRequestId;
        FinalizeRequestId = finalizeRequestId;
        _snapshot = (byte[])candidateSnapshot.Clone();
    }

    internal RollbackCheckpoint Expected { get; }
    internal RollbackCheckpoint Prepared { get; }
    internal RollbackRequestId PrepareRequestId { get; }
    internal RollbackRequestId FinalizeRequestId { get; }
    internal byte[] ExportCandidateCopy() => (byte[])_snapshot.Clone();

    internal byte[] EncodeIntent()
    {
        using MemoryStream stream = new();
        using (BinaryWriter writer = new(stream, Encoding.UTF8, true))
        {
            writer.Write("LSRI"u8);
            writer.Write((ushort)1);
            writer.Write((ushort)0);
            writer.Write(Expected.StoreInstanceId.ToByteArray());
            writer.Write(Expected.Sequence);
            writer.Write(Expected.ExportDigestCopy());
            writer.Write(Prepared.Sequence);
            writer.Write(Prepared.ExportDigestCopy());
            writer.Write(PrepareRequestId.Value.ToByteArray());
            writer.Write(FinalizeRequestId.Value.ToByteArray());
            writer.Write(_snapshot.Length);
        }

        return stream.ToArray();
    }

    internal static RollbackPreparedWrite DecodeIntent(byte[] bytes, byte[] candidateSnapshot)
    {
        if (bytes.Length != RecordLength)
        {
            throw new InvalidDataException("Rollback staging intent has an invalid length.");
        }

        try
        {
            using MemoryStream stream = new(bytes, false);
            using BinaryReader reader = new(stream, Encoding.UTF8);
            if (!reader.ReadBytes(4).AsSpan().SequenceEqual("LSRI"u8) ||
                reader.ReadUInt16() != 1 || reader.ReadUInt16() != 0)
            {
                throw new InvalidDataException("Unsupported rollback intent version.");
            }

            Guid storeId = new(reader.ReadBytes(16));
            ulong expectedSequence = reader.ReadUInt64();
            byte[] expectedDigest = reader.ReadBytes(32);
            ulong preparedSequence = reader.ReadUInt64();
            byte[] preparedDigest = reader.ReadBytes(32);
            RollbackRequestId prepareId = new(new Guid(reader.ReadBytes(16)));
            RollbackRequestId finalizeId = new(new Guid(reader.ReadBytes(16)));
            if (reader.ReadInt32() != candidateSnapshot.Length || stream.Position != stream.Length)
            {
                throw new InvalidDataException("Rollback candidate length does not match its intent.");
            }

            return new RollbackPreparedWrite(
                new RollbackCheckpoint(storeId, expectedSequence, expectedDigest),
                new RollbackCheckpoint(storeId, preparedSequence, preparedDigest),
                prepareId, finalizeId, candidateSnapshot);
        }
        catch (Exception error) when (error is ArgumentException or EndOfStreamException or OverflowException)
        {
            throw new InvalidDataException("Malformed rollback staging intent.", error);
        }
    }
}
