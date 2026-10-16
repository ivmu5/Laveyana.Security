using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Payloads;

/// <summary>Checks stable, supported Generation 1 managed-result representations.</summary>
internal static class ManagedPayloadValidation
{
    internal const int MaximumCiphertextLength = 16 * 1024 * 1024;
    internal const int MaximumApplicationAadLength = 64 * 1024;
    internal const int AeadNonceLength = 12;
    internal const int AeadTagLength = 16;

    internal static void CheckEncryption(KeyReference reference, AlgorithmId algorithm, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> tag, int ciphertextLength)
    {
        CheckReference(reference);
        if (algorithm != WellKnownAlgorithms.Aes256Gcm && algorithm != WellKnownAlgorithms.ChaCha20Poly1305)
        {
            throw new ArgumentException("Unsupported managed AEAD algorithm.", nameof(algorithm));
        }

        if (nonce.Length != AeadNonceLength || tag.Length != AeadTagLength ||
            ciphertextLength is < 0 or > MaximumCiphertextLength)
        {
            throw new ArgumentException("Invalid AEAD nonce, tag or ciphertext length.");
        }
    }

    internal static void CheckReference(KeyReference reference)
    {
        if (!reference.IsDefined)
        {
            throw new ArgumentException("An exact KeyReference is required.", nameof(reference));
        }
    }

    internal static string GetSignatureEncoding(AlgorithmId algorithm, int signatureLength)
    {
        if (algorithm == WellKnownAlgorithms.EcdsaP256Sha256 && signatureLength == 64)
        {
            return "ieee-p1363";
        }

        if (algorithm == WellKnownAlgorithms.RsaPssSha256 && signatureLength is >= 256 and <= 1024)
        {
            return "rsa-pss-raw";
        }

        throw new ArgumentException("Unsupported signature algorithm or signature representation.", nameof(algorithm));
    }

    internal static int GetMacLength(AlgorithmId algorithm)
    {
        if (algorithm == WellKnownAlgorithms.HmacSha256)
        {
            return 32;
        }
        if (algorithm == WellKnownAlgorithms.HmacSha384)
        {
            return 48;
        }
        if (algorithm == WellKnownAlgorithms.HmacSha512)
        {
            return 64;
        }
        throw new ArgumentException("Unsupported managed MAC algorithm.", nameof(algorithm));
    }
}
