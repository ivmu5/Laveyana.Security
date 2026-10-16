namespace Laveyana.Security.Abstractions.Identifiers;

/// <summary>
/// Defines stable Generation 1 algorithm IDs without asserting availability or policy.
/// Availability and the Recommended/Supported/LegacyReadOnly classification are Phase 3 responsibilities.
/// </summary>
public static class WellKnownAlgorithms
{
    /// <summary>SHA-1 for explicitly requested historical verification only.</summary>
    public static AlgorithmId Sha1 { get; } = new("sha-1");

    /// <summary>HMAC-SHA-1 for explicitly requested historical verification only.</summary>
    public static AlgorithmId HmacSha1 { get; } = new("hmac-sha-1");

    /// <summary>SHA-256 hash.</summary>
    public static AlgorithmId Sha256 { get; } = new("sha-256");

    /// <summary>SHA-384 hash.</summary>
    public static AlgorithmId Sha384 { get; } = new("sha-384");

    /// <summary>SHA-512 hash.</summary>
    public static AlgorithmId Sha512 { get; } = new("sha-512");

    /// <summary>HMAC-SHA-256 authentication.</summary>
    public static AlgorithmId HmacSha256 { get; } = new("hmac-sha-256");

    /// <summary>HMAC-SHA-384 authentication.</summary>
    public static AlgorithmId HmacSha384 { get; } = new("hmac-sha-384");

    /// <summary>HMAC-SHA-512 authentication.</summary>
    public static AlgorithmId HmacSha512 { get; } = new("hmac-sha-512");

    /// <summary>Authenticated AES-256-GCM encryption.</summary>
    public static AlgorithmId Aes256Gcm { get; } = new("aes-256-gcm");

    /// <summary>HKDF using SHA-256.</summary>
    public static AlgorithmId HkdfSha256 { get; } = new("hkdf-sha-256");

    /// <summary>PBKDF2 using HMAC-SHA-256.</summary>
    public static AlgorithmId Pbkdf2HmacSha256 { get; } = new("pbkdf2-hmac-sha-256");

    /// <summary>ECDSA P-256 using SHA-256.</summary>
    public static AlgorithmId EcdsaP256Sha256 { get; } = new("ecdsa-p256-sha-256");

    /// <summary>RSA-PSS using SHA-256.</summary>
    public static AlgorithmId RsaPssSha256 { get; } = new("rsa-pss-sha-256");

    /// <summary>ECDH on P-256, requiring subsequent KDF.</summary>
    public static AlgorithmId EcdhP256 { get; } = new("ecdh-p256");

    /// <summary>ChaCha20-Poly1305, subject to platform capability checks.</summary>
    public static AlgorithmId ChaCha20Poly1305 { get; } = new("chacha20-poly1305");
}
