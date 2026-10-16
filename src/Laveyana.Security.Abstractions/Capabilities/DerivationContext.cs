using System.Buffers.Binary;
using System.Text;
using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>Canonical, domain-separated Generation 1 HKDF context. This is public protocol data, not a secret.</summary>
public sealed class DerivationContext
{
    private static readonly byte[] EcdhLabel = "Laveyana.Security/ECDH-P256/HKDF-SHA256/v1"u8.ToArray();
    private static readonly byte[] SymmetricLabel = "Laveyana.Security/Symmetric/HKDF-SHA256/v1"u8.ToArray();
    private readonly byte[] _applicationContext;

    /// <summary>Creates an application-bound context. Both ECDH peers must agree on all values.</summary>
    public DerivationContext(string purpose, ReadOnlySpan<byte> applicationContext, int outputLength = 32)
    {
        if (string.IsNullOrEmpty(purpose) || purpose.Length > 64 ||
            purpose[0] is < 'a' or > 'z' ||
            purpose.Any(c => c is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-' or '_')))
        {
            throw new ArgumentException("Purpose must be a lowercase ASCII token (1-64 characters).", nameof(purpose));
        }

        if (applicationContext.Length is < 1 or > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(applicationContext), "A nonempty, bounded protocol context is required.");
        }

        if (outputLength is < 16 or > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength), "Derived keys must be 16-64 bytes.");
        }

        Purpose = purpose;
        OutputLength = outputLength;
        _applicationContext = applicationContext.ToArray();
    }

    /// <summary>Gets the protocol purpose; different purposes MUST never share a context.</summary>
    public string Purpose { get; }

    /// <summary>Gets the length of the derived key in bytes.</summary>
    public int OutputLength { get; }

    /// <summary>Builds an unambiguous transcript binding both public keys independent of calling order.</summary>
    public byte[] BuildEcdhInfo(ReadOnlySpan<byte> ownSpki, ReadOnlySpan<byte> peerSpki)
    {
        if (ownSpki.IsEmpty || ownSpki.Length > 512 || peerSpki.IsEmpty || peerSpki.Length > 512)
        {
            throw new ArgumentException("P-256 SubjectPublicKeyInfo is invalid or too large.");
        }

        byte[] own = ownSpki.ToArray();
        byte[] peer = peerSpki.ToArray();
        try
        {
            return own.AsSpan().SequenceCompareTo(peer) <= 0
                ? Encode(EcdhLabel, own, peer)
                : Encode(EcdhLabel, peer, own);
        }
        finally
        {
            // Public SPKI is not a secret; temporary arrays are only used for canonical ordering.
        }
    }

    /// <summary>Builds a protocol-specific symmetric HKDF transcript bound to an exact key version.</summary>
    public byte[] BuildSymmetricInfo(KeyReference reference)
    {
        if (!reference.IsDefined)
        {
            throw new ArgumentException("Exact reference required.", nameof(reference));
        }
        return Encode(SymmetricLabel, Encoding.ASCII.GetBytes(reference.ToString()), []);
    }

    private byte[] Encode(byte[] label, byte[] first, byte[] second)
    {
        byte[] purposeBytes = Encoding.ASCII.GetBytes(Purpose);
        int size = checked(4 + label.Length + 4 + purposeBytes.Length + 4 + _applicationContext.Length +
            4 + 4 + first.Length + 4 + second.Length);
        byte[] output = new byte[size];
        int offset = 0;
        Write(label);
        Write(purposeBytes);
        Write(_applicationContext);
        BinaryPrimitives.WriteInt32BigEndian(output.AsSpan(offset, 4), OutputLength);
        offset += 4;
        Write(first);
        Write(second);
        return output;

        void Write(byte[] value)
        {
            BinaryPrimitives.WriteInt32BigEndian(output.AsSpan(offset, 4), value.Length);
            offset += 4;
            value.CopyTo(output, offset);
            offset += value.Length;
        }
    }

    /// <summary>A derived context does not print even public protocol identifiers by default.</summary>
    public override string ToString() => "DerivationContext";
}
