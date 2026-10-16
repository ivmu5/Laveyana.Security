using System.Text;
using Laveyana.Security.Abstractions.Protection;

namespace Laveyana.Security.Abstractions.Persistence;

/// <summary>Untrusted, secret-free versioned bootstrap hint for resolving a persisted protector generation.</summary>
/// <remarks>
/// This record does not contain a root key, authenticate itself, or prove store identity.
/// Compare the instance identity with trusted configuration before resolving the protector,
/// then authenticate protected entries with their original context. Never derive a key from this record.
/// </remarks>
public sealed class ProtectorBootstrapRecord
{
    /// <summary>Creates a bootstrap hint with a non-empty stable store instance identifier.</summary>
    public ProtectorBootstrapRecord(Guid storeInstanceId, ProtectorReference protector)
    {
        if (storeInstanceId == Guid.Empty || !protector.IsDefined)
        {
            throw new ArgumentException("Store instance and protector generation must be defined.");
        }

        StoreInstanceId = storeInstanceId;
        Protector = protector;
    }

    /// <summary>Gets the stable store instance UUID.</summary>
    public Guid StoreInstanceId { get; }

    /// <summary>Gets the stable root-protector identity; no root material is present.</summary>
    public ProtectorReference Protector { get; }

    /// <summary>Serializes canonical LSPB schema version 1 bytes.</summary>
    public byte[] Encode()
    {
        using MemoryStream stream = new();
        using (BinaryWriter writer = new(stream, Encoding.UTF8, true))
        {
            CanonicalWireCodec.WriteHeader(writer, "LSPB"u8, 1);
            CanonicalWireCodec.WriteText(writer, StoreInstanceId.ToString("D"));
            CanonicalWireCodec.WriteText(writer, Protector.ToString());
        }

        return stream.ToArray();
    }

    /// <summary>Validates an untrusted canonical bootstrap hint without trusting its claims.</summary>
    public static ProtectorBootstrapRecord Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is < 8 or > 1024)
        {
            throw new InvalidOperationException("Bootstrap size is invalid.");
        }

        try
        {
            using MemoryStream stream = new(encoded.ToArray(), false);
            using BinaryReader reader = new(stream, Encoding.UTF8);
            CanonicalWireCodec.ReadHeader(reader, "LSPB"u8, 1);
            string instance = CanonicalWireCodec.ReadText(reader);
            string protector = CanonicalWireCodec.ReadText(reader);
            CanonicalWireCodec.EnsureEnd(stream);
            if (!Guid.TryParseExact(instance, "D", out Guid id) || id == Guid.Empty ||
                !string.Equals(id.ToString("D"), instance, StringComparison.Ordinal) ||
                !ProtectorReference.TryParse(protector, out ProtectorReference reference))
            {
                throw new InvalidOperationException("Bootstrap identities are noncanonical or invalid.");
            }

            return new ProtectorBootstrapRecord(id, reference);
        }
        catch (Exception exception) when (exception is EndOfStreamException or DecoderFallbackException or
            FormatException or ArgumentException or OverflowException)
        {
            throw new InvalidOperationException("Malformed persistent record.", exception);
        }
    }

    /// <summary>Avoids writing identifying metadata to generic log messages.</summary>
    public override string ToString() => nameof(ProtectorBootstrapRecord);
}
