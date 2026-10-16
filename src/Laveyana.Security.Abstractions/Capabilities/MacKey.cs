using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>
/// Typed symmetric MAC metadata view; historical verification uses a specified
/// exact reference while forward MAC generation resolves fresh Active metadata.
/// </summary>
public sealed class MacKey
{
    private readonly KeyCapabilityViewCore _core;

    /// <summary>Creates a symmetric MAC metadata view.</summary>
    public MacKey(LogicalKeyHandle handle, IKeyMetadataResolver metadata) =>
        _core = new KeyCapabilityViewCore(handle, metadata, KeyKind.Symmetric);

    /// <summary>Gets stable logical identity.</summary>
    public LogicalKeyHandle Handle => _core.Handle;

    /// <summary>Checks the current Active version for MAC creation.</summary>
    public ValueTask<KeyCapabilityResolution> ResolveForMacAsync(CancellationToken cancellationToken = default) =>
        _core.ForwardAsync(WellKnownCapabilities.Mac, cancellationToken);

    /// <summary>Checks one exact Active/Retired version for MAC verification.</summary>
    public ValueTask<KeyCapabilityResolution> ResolveForVerifyAsync(ExactKeyHandle exactHandle, CancellationToken cancellationToken = default) =>
        _core.HistoricalAsync(exactHandle, WellKnownCapabilities.VerifyMac, cancellationToken);

    /// <summary>Redacts metadata from incidental logs.</summary>
    public override string ToString() => "MacKey";
}
