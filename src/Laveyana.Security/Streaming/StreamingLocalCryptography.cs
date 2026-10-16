using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Streaming;
using Laveyana.Security.Algorithms;

namespace Laveyana.Security.Streaming;

/// <summary>SHA-2 hashing of readable streams with fixed memory use and explicit length bounds.</summary>
public static class StreamingLocalCryptography
{
    /// <summary>Hashes from the current position to EOF, leaving the caller-owned stream open.</summary>
    /// <remarks>The digest is not proof of integrity unless authenticated separately.
    /// Any cancellation, read error, byte-limit violation or truncated expected input throws without returning a digest.</remarks>
    public static async Task<byte[]> HashAsync(Stream message, AlgorithmId algorithm,
        StreamProcessingOptions? options = null, CancellationToken cancellationToken = default)
    {
        AlgorithmPolicy.EnsureAllowed(algorithm, AlgorithmPurpose.Hash, AlgorithmUse.NewOperation);
        HashAlgorithmName hash = algorithm == WellKnownAlgorithms.Sha256 ? HashAlgorithmName.SHA256 :
            algorithm == WellKnownAlgorithms.Sha384 ? HashAlgorithmName.SHA384 :
            algorithm == WellKnownAlgorithms.Sha512 ? HashAlgorithmName.SHA512 :
            throw new CryptographicException("This streaming hash algorithm is not supported.");
        using IncrementalHash incremental = IncrementalHash.CreateHash(hash);
        await StreamHashPump.PumpAsync(message, incremental, options, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return incremental.GetHashAndReset();
    }
}
