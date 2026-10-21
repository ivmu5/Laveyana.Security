using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Laveyana.Security.Maui.NativeKeys;

/// <summary>Converts strict DER-encoded ECDSA P-256 signatures into 64-byte IEEE P1363 signatures.</summary>
/// <remarks>The signature is untrusted until verified with the exact message and public key.</remarks>
public static class EcdsaDerSignatureCodec
{
    /// <summary>Decodes a strict DER SEQUENCE of two positive 256-bit integers.</summary>
    /// <exception cref="CryptographicException">The signature is malformed or outside the P-256 field width.</exception>
    public static byte[] ToP1363(ReadOnlyMemory<byte> derSignature)
    {
        try
        {
            if (derSignature.IsEmpty || derSignature.Length > 80)
            {
                throw new CryptographicException("ECDSA DER signature length is invalid.");
            }

            AsnReader reader = new(derSignature, AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            ReadOnlyMemory<byte> r = sequence.ReadIntegerBytes();
            ReadOnlyMemory<byte> s = sequence.ReadIntegerBytes();
            sequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();

            byte[] result = new byte[64];
            CopyPositiveInteger(r.Span, result.AsSpan(0, 32));
            CopyPositiveInteger(s.Span, result.AsSpan(32, 32));
            return result;
        }
        catch (AsnContentException ex)
        {
            throw new CryptographicException("Malformed DER-encoded ECDSA signature.", ex);
        }
    }

    private static void CopyPositiveInteger(ReadOnlySpan<byte> encoded, Span<byte> destination)
    {
        if (encoded.IsEmpty || encoded.Length > 33)
        {
            throw new CryptographicException("ECDSA component length is invalid.");
        }

        if (encoded[0] == 0)
        {
            encoded = encoded[1..];
            if (encoded.IsEmpty || encoded.Length > 32 || (encoded[0] & 0x80) == 0)
            {
                throw new CryptographicException("Noncanonical positive ECDSA integer.");
            }
        }
        else if ((encoded[0] & 0x80) != 0)
        {
            throw new CryptographicException("Negative ECDSA integer is forbidden.");
        }

        if (encoded.Length > destination.Length)
        {
            throw new CryptographicException("ECDSA component exceeds P-256 width.");
        }

        encoded.CopyTo(destination[(destination.Length - encoded.Length)..]);
    }
}
