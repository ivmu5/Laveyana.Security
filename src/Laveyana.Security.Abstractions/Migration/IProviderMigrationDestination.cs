using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Migration;

/// <summary>Opt-in provider adapter: create a new generation or activate a verified target.</summary>
/// <remarks>Implementations must authorize and durably commit mutations, never reuse source IDs,
/// and report uncertain outcomes as errors. A creation attempt is not automatically idempotent.</remarks>
public interface IProviderMigrationDestination
{
    /// <summary>Identity of the backend this adapter represents.</summary>
    ProviderId ProviderId { get; }

    /// <summary>Creates an independent key generation with new material; never imports source bytes.</summary>
    ValueTask<KeyDescriptor> CreateRegeneratedAsync(KeyName name, AlgorithmId algorithm,
        IReadOnlyList<CapabilityId> capabilities, CancellationToken cancellationToken = default);

    /// <summary>Activates or checks an exact prepared version without silently selecting another.</summary>
    ValueTask<KeyDescriptor> ActivatePreparedAsync(KeyReference prepared,
        CancellationToken cancellationToken = default);
}
