using System.Text;
using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Payloads;

/// <summary>
/// Canonical internal AEAD metadata and separate external application AAD binding.
/// Both Encrypt and Decrypt must supply this exact byte sequence to the AEAD primitive;
/// encoding it does not itself cryptographically authenticate anything.
/// </summary>
public static class EncryptedPayloadAssociatedData
{
    private static readonly byte[] Domain = "Laveyana.Security/managed-aead/v1"u8.ToArray();
    private static readonly UTF8Encoding Utf8 = new(false, true);

    /// <summary>Builds length-delimited versioned AAD that commits to every critical public field.</summary>
    /// <exception cref="ArgumentOutOfRangeException">External AAD exceeds 64 KiB.</exception>
    public static byte[] Build(KeyReference reference, AlgorithmId algorithm, ReadOnlySpan<byte> nonce,
        int ciphertextLength, ReadOnlySpan<byte> applicationAad = default)
    {
        Span<byte> placeholderTag = stackalloc byte[ManagedPayloadValidation.AeadTagLength];
        ManagedPayloadValidation.CheckEncryption(reference, algorithm, nonce, placeholderTag, ciphertextLength);
        if (applicationAad.Length > ManagedPayloadValidation.MaximumApplicationAadLength)
        {
            throw new ArgumentOutOfRangeException(nameof(applicationAad));
        }

        using MemoryStream stream = new();
        using BinaryWriter writer = new(stream, Utf8, true);
        writer.Write(Domain);
        WriteText(writer, reference.ToString());
        WriteText(writer, algorithm.Value);
        writer.Write((byte)nonce.Length);
        writer.Write(nonce);
        writer.Write((byte)ManagedPayloadValidation.AeadTagLength);
        writer.Write((uint)ciphertextLength);
        writer.Write((uint)applicationAad.Length);
        writer.Write(applicationAad);
        writer.Flush();
        return stream.ToArray();
    }

    private static void WriteText(BinaryWriter writer, string value)
    {
        byte[] bytes = Utf8.GetBytes(value);
        writer.Write((ushort)bytes.Length);
        writer.Write(bytes);
    }
}
