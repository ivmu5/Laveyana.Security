using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Algorithms;

/// <summary>
/// Enforces a fail-closed Generation 1 algorithm catalog. Classification is not a
/// guarantee that a provider offers an algorithm or that a key permits its use.
/// </summary>
public static class AlgorithmPolicy
{
    private static readonly IReadOnlyDictionary<AlgorithmId, AlgorithmDescription> Catalog = BuildCatalog();

    /// <summary>Returns a read-only snapshot of the supported catalog.</summary>
    public static IReadOnlyCollection<AlgorithmDescription> All { get; } =
        Array.AsReadOnly(Catalog.Values.ToArray());

    /// <summary>Returns a known algorithm or rejects an unknown/uninitialized identifier.</summary>
    /// <exception cref="CryptographicException">The algorithm is not in the catalog.</exception>
    public static AlgorithmDescription Get(AlgorithmId algorithm)
    {
        if (!algorithm.IsDefined || !Catalog.TryGetValue(algorithm, out AlgorithmDescription? description))
        {
            throw new CryptographicException("Unknown or undefined algorithm. No algorithm fallback is permitted.");
        }

        return description;
    }

    /// <summary>Checks catalog membership, purpose, legacy restrictions and runtime availability.</summary>
    /// <exception cref="CryptographicException">The requested algorithm is not permitted or available.</exception>
    public static void EnsureAllowed(AlgorithmId algorithm, AlgorithmPurpose purpose, AlgorithmUse use)
    {
        if (!Enum.IsDefined(purpose) || !Enum.IsDefined(use))
        {
            throw new ArgumentOutOfRangeException(!Enum.IsDefined(purpose) ? nameof(purpose) : nameof(use));
        }

        AlgorithmDescription item = Get(algorithm);
        if (item.Purpose != purpose)
        {
            throw new CryptographicException("The algorithm does not match the requested operation.");
        }

        if (item.Status == AlgorithmStatus.LegacyReadOnly && use != AlgorithmUse.HistoricalVerification)
        {
            throw new CryptographicException("Legacy algorithms cannot be used for new cryptographic operations.");
        }

        if (item.RequiresPlatformSupport && !IsPlatformSupported(algorithm))
        {
            throw new PlatformNotSupportedException("The requested cryptographic algorithm is not supported on this platform.");
        }
    }

    /// <summary>Checks availability for platform-gated algorithms without downgrading.</summary>
    public static bool IsPlatformSupported(AlgorithmId algorithm)
    {
        AlgorithmDescription item = Get(algorithm);
        if (!item.RequiresPlatformSupport)
        {
            return true;
        }

        return algorithm == WellKnownAlgorithms.ChaCha20Poly1305
            ? ChaCha20Poly1305.IsSupported
            : algorithm == WellKnownAlgorithms.Aes256Gcm && AesGcm.IsSupported;
    }

    private static IReadOnlyDictionary<AlgorithmId, AlgorithmDescription> BuildCatalog()
    {
        AlgorithmDescription[] definitions =
        [
            new(WellKnownAlgorithms.Sha256, AlgorithmPurpose.Hash, AlgorithmStatus.Recommended),
            new(WellKnownAlgorithms.Sha384, AlgorithmPurpose.Hash, AlgorithmStatus.Supported),
            new(WellKnownAlgorithms.Sha512, AlgorithmPurpose.Hash, AlgorithmStatus.Supported),
            new(WellKnownAlgorithms.Sha1, AlgorithmPurpose.Hash, AlgorithmStatus.LegacyReadOnly),
            new(WellKnownAlgorithms.HmacSha256, AlgorithmPurpose.Mac, AlgorithmStatus.Recommended),
            new(WellKnownAlgorithms.HmacSha384, AlgorithmPurpose.Mac, AlgorithmStatus.Supported),
            new(WellKnownAlgorithms.HmacSha512, AlgorithmPurpose.Mac, AlgorithmStatus.Supported),
            new(WellKnownAlgorithms.HmacSha1, AlgorithmPurpose.Mac, AlgorithmStatus.LegacyReadOnly),
            new(WellKnownAlgorithms.HkdfSha256, AlgorithmPurpose.GeneralKdf, AlgorithmStatus.Recommended),
            new(WellKnownAlgorithms.Pbkdf2HmacSha256, AlgorithmPurpose.PasswordKdf, AlgorithmStatus.Recommended),
            new(WellKnownAlgorithms.Aes256Gcm, AlgorithmPurpose.AuthenticatedEncryption, AlgorithmStatus.Recommended, true),
            new(WellKnownAlgorithms.ChaCha20Poly1305, AlgorithmPurpose.AuthenticatedEncryption, AlgorithmStatus.Supported, true),
            new(WellKnownAlgorithms.EcdsaP256Sha256, AlgorithmPurpose.Signature, AlgorithmStatus.Recommended),
            new(WellKnownAlgorithms.RsaPssSha256, AlgorithmPurpose.Signature, AlgorithmStatus.Supported),
            new(WellKnownAlgorithms.EcdhP256, AlgorithmPurpose.KeyAgreement, AlgorithmStatus.Recommended),
        ];

        return new System.Collections.ObjectModel.ReadOnlyDictionary<AlgorithmId, AlgorithmDescription>(
            definitions.ToDictionary(static definition => definition.Id));
    }
}
