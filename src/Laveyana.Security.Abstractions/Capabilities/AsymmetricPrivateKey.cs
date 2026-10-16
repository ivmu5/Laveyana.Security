using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>
/// Typed private asymmetric key view. No private bytes are available. Signing and
/// agreement are independent declared capabilities, not automatic permissions.
/// </summary>
public sealed class AsymmetricPrivateKey
{
    private readonly KeyCapabilityViewCore _core;

    /// <summary>Creates a private-key metadata view.</summary>
    public AsymmetricPrivateKey(LogicalKeyHandle handle, IKeyMetadataResolver metadata) =>
        _core = new KeyCapabilityViewCore(handle, metadata, KeyKind.AsymmetricPrivate);

    /// <summary>Gets stable logical identity.</summary>
    public LogicalKeyHandle Handle => _core.Handle;

    /// <summary>Checks fresh Active metadata for signing support.</summary>
    public ValueTask<KeyCapabilityResolution> ResolveForSignAsync(CancellationToken cancellationToken = default) =>
        _core.ForwardAsync(WellKnownCapabilities.Sign, cancellationToken);

    /// <summary>Checks fresh Active metadata for key agreement support.</summary>
    public ValueTask<KeyCapabilityResolution> ResolveForKeyAgreementAsync(CancellationToken cancellationToken = default) =>
        _core.ForwardAsync(WellKnownCapabilities.KeyAgreement, cancellationToken);

    /// <summary>Redacts metadata from incidental logs.</summary>
    public override string ToString() => "AsymmetricPrivateKey";
}
