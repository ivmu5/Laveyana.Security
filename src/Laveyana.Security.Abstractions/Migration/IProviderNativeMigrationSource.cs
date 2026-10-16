using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Migration;

/// <summary>Optional source-owned secure transfer, with no public raw-key export surface.</summary>
/// <remarks>The implementation must authenticate the destination and protect transport itself.
/// This interface alone is not evidence of a secure channel.</remarks>
public interface IProviderNativeMigrationSource
{
    /// <summary>Transfers an exact source into an independently authenticated native destination.</summary>
    ValueTask<KeyDescriptor> TransferToAsync(KeyReference source, IProviderNativeMigrationDestination destination,
        KeyName destinationName, CancellationToken cancellationToken = default);
}
