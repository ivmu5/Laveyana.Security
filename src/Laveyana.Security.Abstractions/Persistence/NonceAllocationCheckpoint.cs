using System.Text;
using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Persistence;

/// <summary>Portable nonce allocation checkpoint, NOT by itself a rollback-resistant allocator.</summary>
/// <remarks>
/// Only an independent monotonic authority may make this checkpoint authoritative.
/// Plain files, ordinary backups and encrypted metadata do not guarantee nonce non-reuse.
/// </remarks>
public sealed class NonceAllocationCheckpoint
{
    /// <summary>Creates an exact-key counter checkpoint with a positive authority epoch.</summary>
    public NonceAllocationCheckpoint(KeyReference reference, uint prefix, ulong nextCounter, ulong authorityEpoch)
    {
        if (!reference.IsDefined || authorityEpoch == 0)
        {
            throw new ArgumentException("Nonce checkpoint identity and epoch must be defined.");
        }

        Reference = reference;
        Prefix = prefix;
        NextCounter = nextCounter;
        AuthorityEpoch = authorityEpoch;
    }

    /// <summary>Gets the exact version whose nonce domain must never be remapped.</summary>
    public KeyReference Reference { get; }

    /// <summary>Gets the fixed 32-bit nonce prefix in this domain.</summary>
    public uint Prefix { get; }

    /// <summary>Gets the first counter never reserved by the authoritative allocator.</summary>
    public ulong NextCounter { get; }

    /// <summary>Gets a monotonic authority epoch that must be independently protected.</summary>
    public ulong AuthorityEpoch { get; }

    /// <summary>Rejects local rollback or domain changes when comparing trusted consecutive checkpoints.</summary>
    public void ValidateSuccessor(NonceAllocationCheckpoint previous)
    {
        ArgumentNullException.ThrowIfNull(previous);
        if (Reference != previous.Reference || Prefix != previous.Prefix ||
            NextCounter < previous.NextCounter || AuthorityEpoch <= previous.AuthorityEpoch)
        {
            throw new InvalidOperationException("Nonce checkpoint is not a valid monotonic successor.");
        }
    }

    /// <summary>Serializes canonical LSNC schema version 1 bytes.</summary>
    public byte[] Encode()
    {
        using MemoryStream stream = new();
        using (BinaryWriter writer = new(stream, Encoding.UTF8, true))
        {
            CanonicalWireCodec.WriteHeader(writer, "LSNC"u8, 1);
            CanonicalWireCodec.WriteText(writer, Reference.ToString());
            writer.Write(Prefix);
            writer.Write(NextCounter);
            writer.Write(AuthorityEpoch);
        }

        return stream.ToArray();
    }

    /// <summary>Parses untrusted bytes; caller must separately verify authority and rollback resistance.</summary>
    public static NonceAllocationCheckpoint Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is < 8 or > 1024)
        {
            throw new InvalidOperationException("Nonce checkpoint size is invalid.");
        }

        try
        {
            using MemoryStream stream = new(encoded.ToArray(), false);
            using BinaryReader reader = new(stream, Encoding.UTF8);
            CanonicalWireCodec.ReadHeader(reader, "LSNC"u8, 1);
            string referenceText = CanonicalWireCodec.ReadText(reader);
            uint prefix = reader.ReadUInt32();
            ulong counter = reader.ReadUInt64();
            ulong epoch = reader.ReadUInt64();
            CanonicalWireCodec.EnsureEnd(stream);
            if (!KeyReference.TryParse(referenceText, out KeyReference reference) || epoch == 0)
            {
                throw new InvalidOperationException("Nonce checkpoint fields are invalid.");
            }

            return new NonceAllocationCheckpoint(reference, prefix, counter, epoch);
        }
        catch (Exception exception) when (exception is EndOfStreamException or DecoderFallbackException or
            FormatException or ArgumentException or OverflowException)
        {
            throw new InvalidOperationException("Malformed persistent record.", exception);
        }
    }

    /// <summary>Does not expose key identity or nonce state in logs.</summary>
    public override string ToString() => nameof(NonceAllocationCheckpoint);
}
