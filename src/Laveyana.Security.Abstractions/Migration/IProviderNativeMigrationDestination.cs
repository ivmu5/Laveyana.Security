using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Migration;

/// <summary>Optional authenticated native import boundary without a plaintext material API.</summary>
public interface IProviderNativeMigrationDestination : IProviderMigrationDestination
{
    /// <summary>Verifies policy and trust in a source provider before any transfer begins.</summary>
    ValueTask<bool> AcceptsSourceAsync(ProviderId source, AlgorithmId algorithm,
        CancellationToken cancellationToken = default);
}
