using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Migration;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Migration;

/// <summary>Explicit application assertion that all dependent data/references have been durably migrated.</summary>
/// <remarks>The library cannot independently establish the truth of this assertion.
/// Applications must authorize and persist it before submitting the receipt.</remarks>
public sealed class MigrationCutoverReceipt
{
    /// <summary>Records an application-committed cutover under an externally controlled commit ID.</summary>
    public MigrationCutoverReceipt(Guid migrationId, KeyReference source, KeyReference destination,
        string applicationCommitId)
    {
        if (migrationId == Guid.Empty || !source.IsDefined || !destination.IsDefined ||
            string.IsNullOrWhiteSpace(applicationCommitId) || applicationCommitId.Length > 128 ||
            applicationCommitId.Any(c => c is < '!' or > '~'))
        {
            throw new ArgumentException("A valid durable application cutover receipt is required.");
        }

        MigrationId = migrationId;
        Source = source;
        Destination = destination;
        ApplicationCommitId = applicationCommitId;
    }

    /// <summary>Migration identity.</summary>
    public Guid MigrationId { get; }

    /// <summary>Source reference as stored in historical data.</summary>
    public KeyReference Source { get; }

    /// <summary>New exact destination reference.</summary>
    public KeyReference Destination { get; }

    /// <summary>Opaque identifier for the application-owned committed change.</summary>
    public string ApplicationCommitId { get; }

    /// <summary>Redacted label.</summary>
    public override string ToString() => "MigrationCutoverReceipt";
}
