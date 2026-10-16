using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Providers;

/// <summary>
/// Trusted provider-owned signature executor. It MUST enforce revocation and actual access
/// to the exact key version again at execution time; metadata preflight alone is not authorization.
/// The private key must never be exported by this interface.
/// </summary>
public interface IVersionedSignatureKeyOperations
{
    /// <summary>Signs using the exact private version; returns a fresh exclusively caller-owned byte array.</summary>
    ValueTask<byte[]> SignAsync(KeyReference reference, AlgorithmId algorithm, ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default);

    /// <summary>Checks a signature with the exact version's public component; invalid data returns false.</summary>
    ValueTask<bool> VerifyAsync(KeyReference reference, AlgorithmId algorithm, ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> signature, CancellationToken cancellationToken = default);
}
