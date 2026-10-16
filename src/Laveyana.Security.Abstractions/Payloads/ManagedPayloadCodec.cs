using System.Text;
using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Payloads;

/// <summary>
/// Canonical, versioned encodings for four managed result forms.
/// Decoding only validates structure; it never decrypts, authenticates or verifies a MAC/signature.
/// </summary>
public static class ManagedPayloadCodec
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly byte[] EncryptedMagic = "LEP1"u8.ToArray();
    private static readonly byte[] DetachedMagic = "LDP1"u8.ToArray();
    private static readonly byte[] SignatureMagic = "LSP1"u8.ToArray();
    private static readonly byte[] MacMagic = "LMR1"u8.ToArray();

    /// <summary>Hard upper bound on an encoded managed result, including framing.</summary>
    public const int MaximumEncodedLength = 16 * 1024 * 1024 + 4096;

    /// <summary>Encodes an encrypted result in a stable little-endian LEP1 v1 record.</summary>
    public static byte[] Encode(EncryptedPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return Write(EncryptedMagic, writer =>
        {
            WriteIdentity(writer, payload.Reference, payload.Algorithm);
            WriteBytes(writer, payload.ExportNonceCopy());
            WriteBytes(writer, payload.ExportAuthenticationTagCopy());
            WriteBytes(writer, payload.ExportCiphertextCopy());
        });
    }

    /// <summary>Parses a bounded canonical LEP1 record; does not validate its AEAD tag.</summary>
    public static EncryptedPayload DecodeEncrypted(ReadOnlySpan<byte> encoded)
    {
        using MemoryStream stream = Open(encoded);
        using BinaryReader reader = new(stream, Utf8, true);
        ReadHeader(reader, EncryptedMagic);
        (KeyReference reference, AlgorithmId algorithm) = ReadIdentity(reader);
        byte[] nonce = ReadBytes(reader, ManagedPayloadValidation.AeadNonceLength);
        byte[] tag = ReadBytes(reader, ManagedPayloadValidation.AeadTagLength);
        byte[] ciphertext = ReadBytes(reader, ManagedPayloadValidation.MaximumCiphertextLength);
        EnsureEnd(stream);
        ValidateExactLength(nonce.Length, ManagedPayloadValidation.AeadNonceLength);
        ValidateExactLength(tag.Length, ManagedPayloadValidation.AeadTagLength);
        return new EncryptedPayload(reference, algorithm, nonce, ciphertext, tag);
    }

    /// <summary>Encodes a detached metadata record with an explicit ciphertext length.</summary>
    public static byte[] Encode(DetachedEncryptedPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return Write(DetachedMagic, writer =>
        {
            WriteIdentity(writer, payload.Reference, payload.Algorithm);
            WriteBytes(writer, payload.ExportNonceCopy());
            WriteBytes(writer, payload.ExportAuthenticationTagCopy());
            writer.Write((uint)payload.CiphertextLength);
        });
    }

    /// <summary>Parses a detached header without assuming the accompanying ciphertext is genuine.</summary>
    public static DetachedEncryptedPayload DecodeDetached(ReadOnlySpan<byte> encoded)
    {
        using MemoryStream stream = Open(encoded);
        using BinaryReader reader = new(stream, Utf8, true);
        ReadHeader(reader, DetachedMagic);
        (KeyReference reference, AlgorithmId algorithm) = ReadIdentity(reader);
        byte[] nonce = ReadBytes(reader, ManagedPayloadValidation.AeadNonceLength);
        byte[] tag = ReadBytes(reader, ManagedPayloadValidation.AeadTagLength);
        uint ciphertextLength = reader.ReadUInt32();
        EnsureEnd(stream);
        ValidateExactLength(nonce.Length, ManagedPayloadValidation.AeadNonceLength);
        ValidateExactLength(tag.Length, ManagedPayloadValidation.AeadTagLength);
        if (ciphertextLength > ManagedPayloadValidation.MaximumCiphertextLength)
        {
            throw new InvalidDataException("Invalid detached ciphertext length.");
        }

        return new DetachedEncryptedPayload(reference, algorithm, nonce, tag, (int)ciphertextLength);
    }

    /// <summary>Encodes a signature with an explicit canonical signature representation.</summary>
    public static byte[] Encode(SignaturePayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return Write(SignatureMagic, writer =>
        {
            WriteIdentity(writer, payload.Reference, payload.Algorithm);
            WriteText(writer, payload.Encoding);
            WriteBytes(writer, payload.ExportSignatureCopy());
        });
    }

    /// <summary>Parses an exact-key signature; signature verification must be performed separately.</summary>
    public static SignaturePayload DecodeSignature(ReadOnlySpan<byte> encoded)
    {
        using MemoryStream stream = Open(encoded);
        using BinaryReader reader = new(stream, Utf8, true);
        ReadHeader(reader, SignatureMagic);
        (KeyReference reference, AlgorithmId algorithm) = ReadIdentity(reader);
        string encoding = ReadText(reader);
        byte[] signature = ReadBytes(reader, 1024);
        EnsureEnd(stream);
        SignaturePayload payload = new(reference, algorithm, signature);
        if (!string.Equals(payload.Encoding, encoding, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Unexpected signature encoding for algorithm.");
        }

        return payload;
    }

    /// <summary>Encodes an exact-reference HMAC result.</summary>
    public static byte[] Encode(MacResult payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return Write(MacMagic, writer =>
        {
            WriteIdentity(writer, payload.Reference, payload.Algorithm);
            WriteBytes(writer, payload.ExportTagCopy());
        });
    }

    /// <summary>Decodes HMAC metadata; does not verify the MAC.</summary>
    public static MacResult DecodeMac(ReadOnlySpan<byte> encoded)
    {
        using MemoryStream stream = Open(encoded);
        using BinaryReader reader = new(stream, Utf8, true);
        ReadHeader(reader, MacMagic);
        (KeyReference reference, AlgorithmId algorithm) = ReadIdentity(reader);
        byte[] tag = ReadBytes(reader, 64);
        EnsureEnd(stream);
        return new MacResult(reference, algorithm, tag);
    }

    private static byte[] Write(byte[] marker, Action<BinaryWriter> body)
    {
        using MemoryStream stream = new();
        using (BinaryWriter writer = new(stream, Utf8, true))
        {
            writer.Write(marker);
            writer.Write((ushort)1);
            writer.Write((ushort)0);
            body(writer);
            writer.Flush();
        }

        if (stream.Length > MaximumEncodedLength)
        {
            throw new InvalidOperationException("Managed payload exceeds wire bounds.");
        }

        return stream.ToArray();
    }

    private static MemoryStream Open(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is < 8 or > MaximumEncodedLength)
        {
            throw new InvalidDataException("Invalid managed payload record size.");
        }

        return new MemoryStream(encoded.ToArray(), writable: false);
    }

    private static void ReadHeader(BinaryReader reader, ReadOnlySpan<byte> expectedMagic)
    {
        if (!reader.ReadBytes(4).AsSpan().SequenceEqual(expectedMagic))
        {
            throw new InvalidDataException("Incorrect managed payload marker.");
        }

        if (reader.ReadUInt16() != 1)
        {
            throw new NotSupportedException("Unknown managed payload format version.");
        }

        if (reader.ReadUInt16() != 0)
        {
            throw new InvalidDataException("Unknown managed payload flags.");
        }
    }

    private static void WriteIdentity(BinaryWriter writer, KeyReference reference, AlgorithmId algorithm)
    {
        WriteText(writer, reference.ToString());
        WriteText(writer, algorithm.Value);
    }

    private static (KeyReference, AlgorithmId) ReadIdentity(BinaryReader reader)
    {
        string referenceText = ReadText(reader);
        string algorithmText = ReadText(reader);
        if (!KeyReference.TryParse(referenceText, out KeyReference reference) ||
            !AlgorithmId.TryParse(algorithmText, out AlgorithmId algorithm))
        {
            throw new InvalidDataException("Noncanonical managed payload identity.");
        }

        return (reference, algorithm);
    }

    private static void WriteText(BinaryWriter writer, string text)
    {
        byte[] bytes = Utf8.GetBytes(text);
        if (bytes.Length is < 1 or > 256)
        {
            throw new ArgumentException("Invalid managed payload token size.", nameof(text));
        }

        writer.Write((ushort)bytes.Length);
        writer.Write(bytes);
    }

    private static string ReadText(BinaryReader reader)
    {
        int length = reader.ReadUInt16();
        if (length is < 1 or > 256)
        {
            throw new InvalidDataException("Invalid managed payload token size.");
        }

        return Utf8.GetString(ReadExact(reader, length));
    }

    private static void WriteBytes(BinaryWriter writer, ReadOnlySpan<byte> bytes)
    {
        writer.Write((uint)bytes.Length);
        writer.Write(bytes);
    }

    private static byte[] ReadBytes(BinaryReader reader, int maximumLength)
    {
        uint length = reader.ReadUInt32();
        if (length > maximumLength)
        {
            throw new InvalidDataException("Managed payload byte field exceeds its limit.");
        }

        return ReadExact(reader, (int)length);
    }

    private static byte[] ReadExact(BinaryReader reader, int length)
    {
        byte[] bytes = reader.ReadBytes(length);
        if (bytes.Length != length)
        {
            throw new InvalidDataException("Truncated managed payload record.");
        }

        return bytes;
    }

    private static void ValidateExactLength(int actual, int expected)
    {
        if (actual != expected)
        {
            throw new InvalidDataException("Invalid managed payload parameter size.");
        }
    }

    private static void EnsureEnd(MemoryStream stream)
    {
        if (stream.Position != stream.Length)
        {
            throw new InvalidDataException("Trailing bytes in managed payload record.");
        }
    }
}
