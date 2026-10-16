using System.Text;

namespace Laveyana.Security.Abstractions.Persistence;

/// <summary>Bounded canonical binary schema primitives, independent of serializers and CLR enum ordinals.</summary>
internal static class CanonicalWireCodec
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static void WriteHeader(BinaryWriter writer, ReadOnlySpan<byte> magic, ushort version)
    {
        writer.Write(magic);
        writer.Write(version);
        writer.Write((ushort)0);
    }

    internal static void ReadHeader(BinaryReader reader, ReadOnlySpan<byte> magic, ushort version)
    {
        if (!reader.ReadBytes(4).AsSpan().SequenceEqual(magic))
        {
            throw new InvalidOperationException("Unknown persistent record marker.");
        }

        ushort actualVersion = reader.ReadUInt16();
        if (actualVersion != version)
        {
            throw new NotSupportedException("Unsupported persistent record version.");
        }

        if (reader.ReadUInt16() != 0)
        {
            throw new InvalidOperationException("Unknown persistent record flags.");
        }
    }

    internal static void WriteText(BinaryWriter writer, string text)
    {
        byte[] bytes = StrictUtf8.GetBytes(text);
        if (bytes.Length is < 1 or > 256)
        {
            throw new ArgumentException("Persistent text token exceeds schema bounds.");
        }

        writer.Write((ushort)bytes.Length);
        writer.Write(bytes);
    }

    internal static string ReadText(BinaryReader reader)
    {
        int length = reader.ReadUInt16();
        if (length is < 1 or > 256)
        {
            throw new InvalidOperationException("Invalid persistent text token length.");
        }

        byte[] bytes = reader.ReadBytes(length);
        if (bytes.Length != length)
        {
            throw new InvalidOperationException("Truncated persistent text token.");
        }

        return StrictUtf8.GetString(bytes);
    }

    internal static void EnsureEnd(MemoryStream stream)
    {
        if (stream.Position != stream.Length)
        {
            throw new InvalidOperationException("Trailing bytes in persistent record.");
        }
    }
}
