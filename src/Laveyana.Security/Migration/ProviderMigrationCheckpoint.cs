using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Migration;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Migration;

/// <summary>Immutable public record of a single state transition, containing no secret bytes.</summary>
public sealed class ProviderMigrationCheckpoint
{
    internal ProviderMigrationCheckpoint(ProviderMigrationRequest request, AlgorithmId algorithm,
        KeyKind kind, ProviderMigrationStage stage, KeyReference? destination)
    {
        Request = request;
        Algorithm = algorithm;
        Kind = kind;
        Stage = stage;
        Destination = destination;
    }

    /// <summary>Validated source/destination identities and required operations.</summary>
    public ProviderMigrationRequest Request { get; }

    /// <summary>Algorithm frozen from authenticated source version metadata.</summary>
    public AlgorithmId Algorithm { get; }

    /// <summary>Frozen source key type.</summary>
    public KeyKind Kind { get; }

    /// <summary>Last acknowledged step; caller must durably persist the snapshot.</summary>
    public ProviderMigrationStage Stage { get; }

    /// <summary>Exact new generation identity, assigned only after successful preparation.</summary>
    public KeyReference? Destination { get; }

    internal ProviderMigrationCheckpoint Next(ProviderMigrationStage next, KeyReference? destination = null) =>
        new(Request, Algorithm, Kind, next, destination ?? Destination);

    /// <summary>Restores a checkpoint only from an application-authenticated durable journal.</summary>
    /// <remarks>Never trust caller-supplied or unauthenticated checkpoints as authorization.</remarks>
    public static ProviderMigrationCheckpoint Restore(ProviderMigrationRequest request, AlgorithmId algorithm,
        KeyKind kind, ProviderMigrationStage stage, KeyReference? destination)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!algorithm.IsDefined || !Enum.IsDefined(kind) || kind == KeyKind.Unspecified ||
            !Enum.IsDefined(stage) ||
            ((stage == ProviderMigrationStage.Planned) != !destination.HasValue) ||
            (destination.HasValue && (!destination.Value.IsDefined ||
                destination.Value.ProviderId != request.DestinationProviderId ||
                destination.Value.KeyId == request.Source.KeyId)))
        {
            throw new ArgumentException("Invalid persisted migration checkpoint.");
        }

        return new ProviderMigrationCheckpoint(request, algorithm, kind, stage, destination);
    }

    /// <summary>Prevents incidental disclosure of identifiers.</summary>
    public override string ToString() => "ProviderMigrationCheckpoint";
}
