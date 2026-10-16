using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Providers;

/// <summary>
/// Trusted key owner; MUST check exact-version revocation/access inside AgreeAsync.
/// Its implementation must apply HKDF before constructing DerivedKeyLease, never returning a raw ECDH shared secret.
/// </summary>
public interface IVersionedKeyAgreementOperations
{
    /// <summary>Agrees and immediately derives a bounded ephemeral key.</summary>
    ValueTask<DerivedKeyLease> AgreeAsync(KeyReference privateKey, AlgorithmId algorithm,
        ReadOnlyMemory<byte> peerPublicKeySpki, DerivationContext context,
        CancellationToken cancellationToken = default);
}
