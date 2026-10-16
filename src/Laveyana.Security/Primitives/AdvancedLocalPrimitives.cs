using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Algorithms;

namespace Laveyana.Security.Primitives;

/// <summary>
/// Explicit, buffer-oriented interoperability primitives. Callers own input and output
/// buffers and must protect and clear sensitive material. Not a managed key service.
/// </summary>
public static class AdvancedLocalPrimitives
{
    /// <summary>Computes a policy-approved digest and returns the number of bytes written.</summary>
    public static int Hash(
        AlgorithmId algorithm,
        ReadOnlySpan<byte> data,
        Span<byte> destination,
        AlgorithmUse use = AlgorithmUse.NewOperation)
    {
        AlgorithmPolicy.EnsureAllowed(algorithm, AlgorithmPurpose.Hash, use);

        if (algorithm == WellKnownAlgorithms.Sha256)
        {
            return SHA256.HashData(data, destination);
        }

        if (algorithm == WellKnownAlgorithms.Sha384)
        {
            return SHA384.HashData(data, destination);
        }

        if (algorithm == WellKnownAlgorithms.Sha512)
        {
            return SHA512.HashData(data, destination);
        }

        if (algorithm == WellKnownAlgorithms.Sha1)
        {
            return SHA1.HashData(data, destination);
        }

        throw new CryptographicException("No hash implementation is available for the explicitly selected algorithm.");
    }

    /// <summary>Computes an explicit HMAC, writing the tag into caller-owned memory.</summary>
    public static int Hmac(
        AlgorithmId algorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> data,
        Span<byte> destination,
        AlgorithmUse use = AlgorithmUse.NewOperation)
    {
        AlgorithmPolicy.EnsureAllowed(algorithm, AlgorithmPurpose.Mac, use);
        if (key.IsEmpty)
        {
            throw new ArgumentException("HMAC key cannot be empty.", nameof(key));
        }

        if (algorithm == WellKnownAlgorithms.HmacSha256)
        {
            return HMACSHA256.HashData(key, data, destination);
        }

        if (algorithm == WellKnownAlgorithms.HmacSha384)
        {
            return HMACSHA384.HashData(key, data, destination);
        }

        if (algorithm == WellKnownAlgorithms.HmacSha512)
        {
            return HMACSHA512.HashData(key, data, destination);
        }

        if (algorithm == WellKnownAlgorithms.HmacSha1)
        {
            return HMACSHA1.HashData(key, data, destination);
        }

        throw new CryptographicException("No HMAC implementation is available for the explicitly selected algorithm.");
    }

    /// <summary>
    /// Validates a fixed-length HMAC tag using fixed-time comparison for equal lengths.
    /// Tag length remains observable. Legacy algorithms require explicit historical use.
    /// </summary>
    public static bool VerifyHmac(
        AlgorithmId algorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> expectedTag,
        AlgorithmUse use = AlgorithmUse.NewOperation)
    {
        AlgorithmPolicy.EnsureAllowed(algorithm, AlgorithmPurpose.Mac, use);
        if (key.IsEmpty)
        {
            throw new ArgumentException("HMAC key cannot be empty.", nameof(key));
        }

        int requiredLength = algorithm == WellKnownAlgorithms.HmacSha1 ? 20
            : algorithm == WellKnownAlgorithms.HmacSha256 ? 32
            : algorithm == WellKnownAlgorithms.HmacSha384 ? 48
            : 64;

        if (expectedTag.Length != requiredLength)
        {
            return false;
        }

        Span<byte> actual = stackalloc byte[64];
        try
        {
            int written = Hmac(algorithm, key, data, actual, use);
            return CryptographicOperations.FixedTimeEquals(actual[..written], expectedTag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    /// <summary>
    /// Performs RFC 5869 HKDF-SHA-256 Extract+Expand. Empty salt or info is supported
    /// only by this explicit advanced API. Output must not exceed 255 hash blocks.
    /// </summary>
    public static void HkdfSha256(
        ReadOnlySpan<byte> inputKeyMaterial,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        Span<byte> destination)
    {
        AlgorithmPolicy.EnsureAllowed(
            WellKnownAlgorithms.HkdfSha256, AlgorithmPurpose.GeneralKdf, AlgorithmUse.NewOperation);
        if (inputKeyMaterial.IsEmpty)
        {
            throw new ArgumentException("Input key material cannot be empty.", nameof(inputKeyMaterial));
        }

        if (destination.IsEmpty || destination.Length > 255 * 32)
        {
            throw new ArgumentOutOfRangeException(nameof(destination), "HKDF output must be between 1 and 8160 bytes.");
        }

        HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, destination, salt, info);
    }

    /// <summary>
    /// Derives PBKDF2-HMAC-SHA-256 for historical verification, using the explicitly
    /// stored work factor. This method must not generate new password-verifier values.
    /// </summary>
    public static void DeriveHistoricalPbkdf2Sha256(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        int historicalIterations,
        Span<byte> destination)
    {
        AlgorithmPolicy.EnsureAllowed(
            WellKnownAlgorithms.Pbkdf2HmacSha256, AlgorithmPurpose.PasswordKdf, AlgorithmUse.HistoricalVerification);
        if (historicalIterations < 1 || historicalIterations > Pbkdf2WorkFactor.MaximumIterations)
        {
            throw new ArgumentOutOfRangeException(nameof(historicalIterations));
        }

        if (salt.IsEmpty || destination.IsEmpty || destination.Length > 4096)
        {
            throw new ArgumentException("PBKDF2 salt must not be empty and output must be 1 to 4096 bytes.");
        }

        Rfc2898DeriveBytes.Pbkdf2(password, salt, destination, historicalIterations, HashAlgorithmName.SHA256);
    }
}
