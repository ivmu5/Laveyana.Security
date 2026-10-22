using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Laveyana.Security.Maui.NativeKeys;

/// <summary>Converts Apple Security's uncompressed P-256 X9.63 public points to SPKI.</summary>
/// <remarks>
/// The conversion never handles private material. An elliptic curve point must be
/// independently checked against the claimed NIST P-256 curve before trust.
/// </remarks>
public static class AppleP256PublicKeyCodec
{
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";
    private const string NistP256Oid = "1.2.840.10045.3.1.7";

    /// <summary>
    /// Converts a 65-byte, uncompressed 0x04 || X || Y point into a
    /// validated, canonical SubjectPublicKeyInfo representation.
    /// </summary>
    public static byte[] ToSubjectPublicKeyInfo(ReadOnlySpan<byte> x963Point)
    {
        if (x963Point.Length != 65 || x963Point[0] != 0x04)
        {
            throw new CryptographicException("Expected an uncompressed P-256 X9.63 public point.");
        }

        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier(EcPublicKeyOid);
        writer.WriteObjectIdentifier(NistP256Oid);
        writer.PopSequence();
        writer.WriteBitString(x963Point);
        writer.PopSequence();

        byte[] spki = writer.Encode();
        // Parse and validate the point against the NIST P-256 curve. Merely
        // wrapping arbitrary bytes in an ASN.1 container is insufficient.
        try
        {
            using ECDsa validator = ECDsa.Create();
            validator.ImportSubjectPublicKeyInfo(spki, out int consumed);
            if (consumed != spki.Length || validator.KeySize != 256)
            {
                throw new CryptographicException("Invalid NIST P-256 public key.");
            }
        }
        catch (PlatformNotSupportedException exception)
        {
            // Windows CNG can report an off-curve point as an unsupported
            // curve. Normalize that fail-closed validation error.
            throw new CryptographicException("P-256 public key validation failed.", exception);
        }

        return spki;
    }
}
