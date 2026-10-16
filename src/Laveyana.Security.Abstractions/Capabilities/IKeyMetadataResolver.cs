using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>
/// Supplies fresh metadata snapshots. Implementations must not retain a resolved
/// Active version across invocations; snapshots are not authorization grants.
/// </summary>
/// <remarks>
/// Implementations must honor cancellation and return null for absent identities.
/// They may represent software, HSM, remote or non-exportable keys. This contract
/// intentionally does not expose raw material or perform cryptographic operations.
/// </remarks>
public interface IKeyMetadataResolver
{
    /// <summary>Retrieves the current logical generation snapshot.</summary>
    ValueTask<KeyDescriptor?> FindLogicalAsync(LogicalKeyHandle handle, CancellationToken cancellationToken = default);

    /// <summary>Retrieves one exact material-version snapshot.</summary>
    ValueTask<KeyVersionDescriptor?> FindExactAsync(ExactKeyHandle handle, CancellationToken cancellationToken = default);
}
