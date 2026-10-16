using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>Common identity and metadata dependencies for strongly typed key views.</summary>
internal sealed class KeyCapabilityViewCore
{
    private readonly IKeyMetadataResolver _metadata;
    private readonly KeyKind _kind;

    internal KeyCapabilityViewCore(LogicalKeyHandle handle, IKeyMetadataResolver metadata, KeyKind kind)
    {
        if (!handle.IsDefined)
        {
            throw new ArgumentException("The logical key handle must be defined.", nameof(handle));
        }

        ArgumentNullException.ThrowIfNull(metadata);
        Handle = handle;
        _metadata = metadata;
        _kind = kind;
    }

    internal LogicalKeyHandle Handle { get; }

    internal ValueTask<KeyCapabilityResolution> ForwardAsync(CapabilityId capability, CancellationToken cancellationToken) =>
        KeyCapabilityPreflight.ForwardAsync(_metadata, Handle, _kind, capability, cancellationToken);

    internal ValueTask<KeyCapabilityResolution> HistoricalAsync(ExactKeyHandle exactHandle, CapabilityId capability, CancellationToken cancellationToken) =>
        KeyCapabilityPreflight.HistoricalAsync(_metadata, Handle, exactHandle, _kind, capability, cancellationToken);
}
