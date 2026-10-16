using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Migration;

/// <summary>An explicit request for a different provider and a newly named key generation.</summary>
public sealed class ProviderMigrationRequest
{
    /// <summary>Validates all identities and captures a defensive capability set.</summary>
    public ProviderMigrationRequest(Guid migrationId, KeyReference source, ProviderId destinationProviderId,
        KeyName destinationName, ProviderMigrationMode mode, IEnumerable<CapabilityId> requiredCapabilities)
    {
        if (migrationId == Guid.Empty || !source.IsDefined || !destinationProviderId.IsDefined ||
            destinationProviderId == source.ProviderId || !destinationName.IsDefined ||
            !Enum.IsDefined(mode))
        {
            throw new ArgumentException("Migration requires distinct, defined source and destination identities.");
        }

        ArgumentNullException.ThrowIfNull(requiredCapabilities);
        CapabilityId[] copy = requiredCapabilities.Take(65).ToArray();
        if (copy.Length == 0 || copy.Length > 64 || copy.Any(x => !x.IsDefined) ||
            copy.Distinct().Count() != copy.Length)
        {
            throw new ArgumentException("Between 1 and 64 distinct capabilities are required.", nameof(requiredCapabilities));
        }

        Array.Sort(copy, (x, y) => StringComparer.Ordinal.Compare(x.Value, y.Value));
        MigrationId = migrationId;
        Source = source;
        DestinationProviderId = destinationProviderId;
        DestinationName = destinationName;
        Mode = mode;
        RequiredCapabilities = Array.AsReadOnly(copy);
    }

    /// <summary>Application-defined durable operation identity.</summary>
    public Guid MigrationId { get; }

    /// <summary>Exact source identity, including its original version.</summary>
    public KeyReference Source { get; }

    /// <summary>Distinct target provider; never an alias.</summary>
    public ProviderId DestinationProviderId { get; }

    /// <summary>New target key name.</summary>
    public KeyName DestinationName { get; }

    /// <summary>Material acquisition strategy.</summary>
    public ProviderMigrationMode Mode { get; }

    /// <summary>Operations required of the destination version.</summary>
    public IReadOnlyList<CapabilityId> RequiredCapabilities { get; }

    /// <summary>Does not reveal identities in incidental logs.</summary>
    public override string ToString() => "ProviderMigrationRequest";
}
