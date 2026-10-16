using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>
/// Typed symmetric encryption key view. Forward encryption selects current Active
/// material on each call; historical decryption pins the supplied exact version.
/// Neither method performs encryption or authorizes cryptographic operations.
/// </summary>
public sealed class EncryptionKey
{
    private readonly KeyCapabilityViewCore _core;

    /// <summary>Creates an identity-bound encryption metadata view.</summary>
    public EncryptionKey(LogicalKeyHandle handle, IKeyMetadataResolver metadata) =>
        _core = new KeyCapabilityViewCore(handle, metadata, KeyKind.Symmetric);

    /// <summary>Gets the stable logical identity, never a cached Active version.</summary>
    public LogicalKeyHandle Handle => _core.Handle;

    /// <summary>Checks current Active metadata for symmetric encryption.</summary>
    public ValueTask<KeyCapabilityResolution> ResolveForEncryptAsync(CancellationToken cancellationToken = default) =>
        _core.ForwardAsync(WellKnownCapabilities.Encrypt, cancellationToken);

    /// <summary>Checks explicit Active/Retired metadata for historical decryption.</summary>
    public ValueTask<KeyCapabilityResolution> ResolveForDecryptAsync(ExactKeyHandle exactHandle, CancellationToken cancellationToken = default) =>
        _core.HistoricalAsync(exactHandle, WellKnownCapabilities.Decrypt, cancellationToken);

    /// <summary>Redacts metadata from incidental logs.</summary>
    public override string ToString() => "EncryptionKey";
}
