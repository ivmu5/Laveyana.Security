using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Migration;

/// <summary>Independent source-side retirement with authoritative application dependency guards.</summary>
/// <remarks>Implementations must verify authorization, retention and cutover receipts themselves;
/// this interface must not be implemented as an unconditional force delete.</remarks>
public interface IProviderMigrationSourceLifecycle
{
    /// <summary>Retires a source only after independently validating the committed cutover.</summary>
    ValueTask RetireAfterCutoverAsync(KeyReference source, Guid migrationId,
        CancellationToken cancellationToken = default);

    /// <summary>Deletes source material only after provider-enforced retention and usage checks.</summary>
    ValueTask DeleteAfterCutoverAsync(KeyReference source, Guid migrationId,
        CancellationToken cancellationToken = default);
}
