using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Handles;

namespace Laveyana.Security.Abstractions.Providers;

/// <summary>Optional authenticated-by-caller ECDH + mandatory HKDF operation boundary.</summary>
public interface IManagedKeyAgreementBackend : IKeyProviderBackend
{
    /// <summary>Derives an ephemeral key with the current Active P-256 private version; never returns raw ECDH secret.</summary>
    ValueTask<DerivedKeyLease> AgreeAsync(LogicalKeyHandle privateKey, ReadOnlyMemory<byte> peerPublicKeySpki,
        DerivationContext context, CancellationToken cancellationToken = default);
}
