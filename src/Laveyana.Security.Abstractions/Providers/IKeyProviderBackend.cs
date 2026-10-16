using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Providers;

/// <summary>
/// External provider extension boundary for stable identity, fresh metadata and
/// advertised capabilities. A backend can be implemented using Abstractions alone.
/// </summary>
/// <remarks>
/// Each backend instance must retain one stable ProviderId for its lifetime.
/// Metadata reads must use the exact key identity received and respect cancellation.
/// The declarations here do not authorize a cryptographic operation. Backend-owned
/// atomic operations, enforcement and material persistence are defined in later phases.
/// </remarks>
public interface IKeyProviderBackend : IKeyMetadataResolver
{
    /// <summary>Gets the immutable persistent provider identity, never its runtime alias.</summary>
    ProviderId ProviderId { get; }

    /// <summary>
    /// Gets a fresh immutable snapshot of capabilities advertised by this provider.
    /// Capabilities can change between calls; do not treat a snapshot as authorization.
    /// </summary>
    ValueTask<ProviderCapabilitySnapshot> GetCapabilitiesAsync(CancellationToken cancellationToken = default);
}
