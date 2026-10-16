using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>
/// Typed public-only asymmetric key metadata view. Historical signature verification
/// pins a supplied exact version. Asymmetric encryption is not implicitly enabled.
/// </summary>
public sealed class AsymmetricPublicKey
{
    private readonly KeyCapabilityViewCore _core;

    /// <summary>Creates a public-key metadata view.</summary>
    public AsymmetricPublicKey(LogicalKeyHandle handle, IKeyMetadataResolver metadata) =>
        _core = new KeyCapabilityViewCore(handle, metadata, KeyKind.AsymmetricPublic);

    /// <summary>Gets stable logical identity.</summary>
    public LogicalKeyHandle Handle => _core.Handle;

    /// <summary>Checks one exact Active/Retired public version for signature verification.</summary>
    public ValueTask<KeyCapabilityResolution> ResolveForVerifySignatureAsync(ExactKeyHandle exactHandle, CancellationToken cancellationToken = default) =>
        _core.HistoricalAsync(exactHandle, WellKnownCapabilities.VerifySignature, cancellationToken);

    /// <summary>Redacts metadata from incidental logs.</summary>
    public override string ToString() => "AsymmetricPublicKey";
}
