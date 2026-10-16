using System.Text;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Storage;

namespace Laveyana.Security.FileSystem.Storage;

/// <summary>Strict versioned encoding of one entire store generation.</summary>
internal static class FileSystemSnapshotCodec
{
    internal const int MaximumBodyLength = 48 * 1024 * 1024;
    internal const int MaximumRecords = 2048;
    private const int MaximumMaterialsPerRecord = 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal sealed class Record(KeyStoreEntry entry, Dictionary<KeyVersion, ProtectedStoreEnvelope> materials)
    {
        internal KeyStoreEntry Entry { get; set; } = entry;
        internal Dictionary<KeyVersion, ProtectedStoreEnvelope> Materials { get; set; } = materials;
    }

    internal sealed class State
    {
        internal Dictionary<(ProviderId, KeyId), Record> Records { get; } = new();
        internal Dictionary<(ProviderId, KeyName), KeyId> Names { get; } = new();
        internal HashSet<(ProviderId, KeyId)> UsedIds { get; } = new();
    }

    internal static byte[] EncodeBody(State state)
    {
        if (state.Records.Count > MaximumRecords || state.UsedIds.Count > MaximumRecords * 8 ||
            state.Records.Values.Any(item => item.Materials.Count > MaximumMaterialsPerRecord))
        {
            throw new InvalidOperationException("Store history or material count exceeds schema bounds.");
        }

        using MemoryStream stream = new();
        using (BinaryWriter writer = new(stream, StrictUtf8, true))
        {
            writer.Write("LSFB"u8);
            writer.Write((ushort)1);
            writer.Write((ushort)0);
            writer.Write(state.UsedIds.Count);
            foreach ((ProviderId provider, KeyId key) in state.UsedIds
                .OrderBy(item => item.Item1.ToString(), StringComparer.Ordinal)
                .ThenBy(item => item.Item2.ToString(), StringComparer.Ordinal))
            {
                WriteToken(writer, provider.ToString());
                WriteToken(writer, key.ToString());
            }

            writer.Write(state.Records.Count);
            foreach (Record record in state.Records.Values
                .OrderBy(item => item.Entry.ProviderId.ToString(), StringComparer.Ordinal)
                .ThenBy(item => item.Entry.KeyId.ToString(), StringComparer.Ordinal))
            {
                KeyStoreEntry entry = record.Entry;
                WriteToken(writer, entry.ProviderId.ToString());
                WriteToken(writer, entry.KeyId.ToString());
                WriteToken(writer, entry.Name.Value);
                writer.Write(entry.Revision.Value);
                WriteEnvelope(writer, entry.ProtectedMetadata);
                writer.Write(record.Materials.Count);
                foreach (KeyValuePair<KeyVersion, ProtectedStoreEnvelope> material in record.Materials
                    .OrderBy(item => item.Key.Value))
                {
                    writer.Write(material.Key.Value);
                    WriteEnvelope(writer, material.Value);
                }
            }
        }

        if (stream.Length > MaximumBodyLength)
        {
            throw new InvalidOperationException("Store snapshot exceeds the size limit.");
        }

        return stream.ToArray();
    }

    internal static State DecodeBody(byte[] bytes)
    {
        if (bytes.Length is < 16 or > MaximumBodyLength)
        {
            throw new InvalidDataException("Store snapshot length is invalid.");
        }

        try
        {
            using MemoryStream stream = new(bytes, false);
            using BinaryReader reader = new(stream, StrictUtf8);
            if (!reader.ReadBytes(4).AsSpan().SequenceEqual("LSFB"u8) ||
                reader.ReadUInt16() != 1 || reader.ReadUInt16() != 0)
            {
                throw new InvalidDataException("Unsupported store snapshot schema.");
            }

            State state = new();
            int historical = ReadCount(reader, MaximumRecords * 8);
            for (int i = 0; i < historical; i++)
            {
                ProviderId provider = ProviderId.Parse(ReadToken(reader));
                KeyId key = KeyId.Parse(ReadToken(reader));
                if (!state.UsedIds.Add((provider, key)))
                {
                    throw new InvalidDataException("Duplicate historical KeyId.");
                }
            }

            int count = ReadCount(reader, MaximumRecords);
            for (int i = 0; i < count; i++)
            {
                ProviderId provider = ProviderId.Parse(ReadToken(reader));
                KeyId key = KeyId.Parse(ReadToken(reader));
                KeyName name = KeyName.Parse(ReadToken(reader));
                KeyStoreRevision revision = new(reader.ReadInt64());
                ProtectedStoreEnvelope metadata = ReadEnvelope(reader, ProtectionPurpose.Metadata);
                KeyStoreEntry entry = new(provider, key, name, revision, metadata);
                Dictionary<KeyVersion, ProtectedStoreEnvelope> materials = new();
                int materialCount = ReadCount(reader, MaximumMaterialsPerRecord);
                for (int j = 0; j < materialCount; j++)
                {
                    KeyVersion version = new(reader.ReadInt64());
                    if (!materials.TryAdd(version, ReadEnvelope(reader, ProtectionPurpose.KeyMaterial)))
                    {
                        throw new InvalidDataException("Duplicate material version.");
                    }
                }

                if (!state.UsedIds.Contains((provider, key)) ||
                    !state.Records.TryAdd((provider, key), new Record(entry, materials)) ||
                    !state.Names.TryAdd((provider, name), key))
                {
                    throw new InvalidDataException("Inconsistent KeyId or name binding.");
                }
            }

            if (stream.Position != stream.Length)
            {
                throw new InvalidDataException("Trailing bytes in store snapshot.");
            }

            return state;
        }
        catch (Exception error) when (error is ArgumentException or FormatException or EndOfStreamException or
            OverflowException or DecoderFallbackException)
        {
            throw new InvalidDataException("Malformed store snapshot.", error);
        }
    }

    internal static byte[] EncodeFile(byte[] body, ProtectedStoreEnvelope authentication)
    {
        if (body.Length > MaximumBodyLength || authentication.Purpose != ProtectionPurpose.Metadata)
        {
            throw new ArgumentException("Invalid store snapshot envelope.");
        }

        using MemoryStream stream = new();
        using (BinaryWriter writer = new(stream, StrictUtf8, true))
        {
            writer.Write("LSFS"u8);
            writer.Write((ushort)1);
            writer.Write((ushort)0);
            writer.Write(body.Length);
            writer.Write(body);
            WriteEnvelope(writer, authentication);
        }

        return stream.ToArray();
    }

    internal static (byte[] Body, ProtectedStoreEnvelope Authentication) DecodeFile(byte[] bytes)
    {
        if (bytes.Length < 24 || bytes.Length > MaximumBodyLength + ProtectedStoreEnvelope.MaximumEncodedLength + 256)
        {
            throw new InvalidDataException("Store file size is invalid.");
        }

        try
        {
            using MemoryStream stream = new(bytes, false);
            using BinaryReader reader = new(stream, StrictUtf8);
            if (!reader.ReadBytes(4).AsSpan().SequenceEqual("LSFS"u8) ||
                reader.ReadUInt16() != 1 || reader.ReadUInt16() != 0)
            {
                throw new InvalidDataException("Unsupported store file schema.");
            }

            int length = reader.ReadInt32();
            if (length is < 16 or > MaximumBodyLength || length > stream.Length - stream.Position)
            {
                throw new InvalidDataException("Invalid store body length.");
            }

            byte[] body = reader.ReadBytes(length);
            ProtectedStoreEnvelope signature = ReadEnvelope(reader, ProtectionPurpose.Metadata);
            if (stream.Position != stream.Length)
            {
                throw new InvalidDataException("Trailing bytes in store file.");
            }

            return (body, signature);
        }
        catch (Exception error) when (error is ArgumentException or FormatException or EndOfStreamException or
            OverflowException or DecoderFallbackException)
        {
            throw new InvalidDataException("Malformed store file.", error);
        }
    }

    private static void WriteEnvelope(BinaryWriter writer, ProtectedStoreEnvelope envelope)
    {
        WriteToken(writer, envelope.Protector.ToString());
        writer.Write((byte)envelope.Purpose);
        writer.Write(envelope.EncodedLength);
        writer.Write(envelope.ExportEncodedCopy());
    }

    private static ProtectedStoreEnvelope ReadEnvelope(BinaryReader reader, ProtectionPurpose purpose)
    {
        ProtectorReference reference = ProtectorReference.Parse(ReadToken(reader));
        if (reader.ReadByte() != (byte)purpose)
        {
            throw new InvalidDataException("Invalid envelope purpose.");
        }

        int length = reader.ReadInt32();
        if (length is < 1 or > ProtectedStoreEnvelope.MaximumEncodedLength ||
            length > reader.BaseStream.Length - reader.BaseStream.Position)
        {
            throw new InvalidDataException("Envelope length is invalid.");
        }

        return new ProtectedStoreEnvelope(reference, purpose, reader.ReadBytes(length));
    }

    private static void WriteToken(BinaryWriter writer, string value)
    {
        byte[] encoded = StrictUtf8.GetBytes(value);
        if (encoded.Length is < 1 or > 160)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        writer.Write((ushort)encoded.Length);
        writer.Write(encoded);
    }

    private static string ReadToken(BinaryReader reader)
    {
        ushort length = reader.ReadUInt16();
        if (length is < 1 or > 160 || length > reader.BaseStream.Length - reader.BaseStream.Position)
        {
            throw new InvalidDataException("Invalid token length.");
        }

        return StrictUtf8.GetString(reader.ReadBytes(length));
    }

    private static int ReadCount(BinaryReader reader, int maximum)
    {
        int count = reader.ReadInt32();
        return count >= 0 && count <= maximum ? count : throw new InvalidDataException("Invalid item count.");
    }
}
