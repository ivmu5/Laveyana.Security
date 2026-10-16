using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>Typed symmetric derivation view, resolving Active on every invocation.</summary>
public sealed class DerivationKey
{
    private readonly KeyCapabilityViewCore _core;

    /// <summary>Creates a symmetric derivation metadata view.</summary>
    public DerivationKey(LogicalKeyHandle handle, IKeyMetadataResolver metadata) =>
        _core = new KeyCapabilityViewCore(handle, metadata, KeyKind.Symmetric);

    /// <summary>Gets stable logical identity.</summary>
    public LogicalKeyHandle Handle => _core.Handle;

    /// <summary>Checks fresh Active metadata for derivation support.</summary>
    public ValueTask<KeyCapabilityResolution> ResolveForDeriveAsync(CancellationToken cancellationToken = default) =>
        _core.ForwardAsync(WellKnownCapabilities.Derive, cancellationToken);

    /// <summary>Redacts metadata from incidental logs.</summary>
    public override string ToString() => "DerivationKey";
}
