using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Algorithms;

namespace Laveyana.Security.Primitives;

/// <summary>
/// Safe-default, stateless local cryptographic primitives. Sensitive return values
/// and destination buffers remain caller-owned unless explicitly transferred into
/// a Phase 4 sensitive material lease.
/// </summary>
public static class LocalCryptography
{
    /// <summary>Bounds one-shot random allocations; larger outputs use FillRandom in chunks.</summary>
    public const int MaximumRandomAllocation = 1024 * 1024;

    /// <summary>Creates cryptographically random bytes in caller-owned memory.</summary>
    public static byte[] GenerateRandomBytes(int byteCount)
    {
        if (byteCount < 1 || byteCount > MaximumRandomAllocation)
        {
            throw new ArgumentOutOfRangeException(nameof(byteCount));
        }

        return RandomNumberGenerator.GetBytes(byteCount);
    }

    /// <summary>Fills a caller-owned buffer from the operating system's secure RNG.</summary>
    public static void FillRandom(Span<byte> destination) => RandomNumberGenerator.Fill(destination);

    /// <summary>Computes the recommended SHA-256 digest.</summary>
    public static byte[] Sha256(ReadOnlySpan<byte> data)
    {
        AlgorithmPolicy.EnsureAllowed(WellKnownAlgorithms.Sha256, AlgorithmPurpose.Hash, AlgorithmUse.NewOperation);
        return SHA256.HashData(data);
    }

    /// <summary>
    /// Compares two values in fixed time for equal lengths. As with the .NET
    /// primitive, differing lengths are not hidden from an observer.
    /// </summary>
    public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        CryptographicOperations.FixedTimeEquals(left, right);

    /// <summary>Computes HMAC-SHA-256 using a key of at least 256 bits.</summary>
    public static byte[] HmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        if (key.Length < 32)
        {
            throw new ArgumentException("New HMAC keys must contain at least 32 bytes.", nameof(key));
        }

        AlgorithmPolicy.EnsureAllowed(WellKnownAlgorithms.HmacSha256, AlgorithmPurpose.Mac, AlgorithmUse.NewOperation);
        return HMACSHA256.HashData(key, data);
    }

    /// <summary>Verifies a complete 32-byte HMAC-SHA-256 tag.</summary>
    public static bool VerifyHmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> expectedTag)
    {
        if (key.Length < 32)
        {
            throw new ArgumentException("The HMAC key must contain at least 32 bytes.", nameof(key));
        }

        return AdvancedLocalPrimitives.VerifyHmac(
            WellKnownAlgorithms.HmacSha256, key, data, expectedTag);
    }

    /// <summary>
    /// Derives 16..8160 bytes using HKDF-SHA-256 with an explicit independent salt
    /// and nonempty protocol-specific info. The caller owns and clears the output.
    /// </summary>
    public static void DeriveHkdfSha256(
        ReadOnlySpan<byte> inputKeyMaterial,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        Span<byte> destination)
    {
        if (inputKeyMaterial.Length < 16)
        {
            throw new ArgumentException("Input key material must contain at least 16 bytes.", nameof(inputKeyMaterial));
        }

        if (salt.Length < 16)
        {
            throw new ArgumentException("New derivations require a salt of at least 16 bytes.", nameof(salt));
        }

        if (info.IsEmpty)
        {
            throw new ArgumentException("A protocol-specific, nonempty info context is required.", nameof(info));
        }

        if (destination.Length < 16 || destination.Length > 255 * 32)
        {
            throw new ArgumentOutOfRangeException(nameof(destination));
        }

        AdvancedLocalPrimitives.HkdfSha256(inputKeyMaterial, salt, info, destination);
    }

    /// <summary>
    /// Derives a new password-based key using versioned PBKDF2-HMAC-SHA-256 policy.
    /// Persist the iteration count, version and salt with the verifier metadata.
    /// This is not a full password-storage or authentication protocol.
    /// </summary>
    public static void DerivePbkdf2Sha256(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        Pbkdf2WorkFactor workFactor,
        Span<byte> destination)
    {
        workFactor.Validate();
        if (password.IsEmpty)
        {
            throw new ArgumentException("A new PBKDF2 derivation requires a nonempty password.", nameof(password));
        }

        if (salt.Length < 16)
        {
            throw new ArgumentException("New PBKDF2 derivations require a salt of at least 16 bytes.", nameof(salt));
        }

        if (destination.Length < 16 || destination.Length > 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(destination));
        }

        AlgorithmPolicy.EnsureAllowed(
            WellKnownAlgorithms.Pbkdf2HmacSha256, AlgorithmPurpose.PasswordKdf, AlgorithmUse.NewOperation);
        Rfc2898DeriveBytes.Pbkdf2(password, salt, destination, workFactor.Iterations, HashAlgorithmName.SHA256);
    }
}
