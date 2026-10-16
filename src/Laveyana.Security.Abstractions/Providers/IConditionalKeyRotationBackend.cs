using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Providers;

/// <summary>
/// Optional backend capability for a version-fenced, atomic cryptographic key rotation.
/// Implementations MUST compare the active version and commit exactly once in one
/// authoritative conditional transaction. A stale expected version MUST NOT rotate.
/// </summary>
public interface IConditionalKeyRotationBackend : IKeyProviderBackend
{
    /// <summary>
    /// Rotates only if the authoritative active version still equals expectedActiveVersion.
    /// An unknown commit outcome must be reported as an error, never retried here.
    /// </summary>
    ValueTask<KeyDescriptor> RotateIfCurrentAsync(LogicalKeyHandle handle,
        KeyVersion expectedActiveVersion, CancellationToken cancellationToken = default);
}
