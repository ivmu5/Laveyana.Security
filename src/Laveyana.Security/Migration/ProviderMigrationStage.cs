using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Migration;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Migration;

/// <summary>Ordered application-persisted states; not a durable transaction on its own.</summary>
public enum ProviderMigrationStage
{
    /// <summary>Indicates that the source and migration plan have been validated.</summary>
    Planned = 1,
    /// <summary>Indicates that the destination key has been prepared.</summary>
    Prepared = 2,
    /// <summary>Indicates that the prepared destination was verified.</summary>
    Validated = 3,
    /// <summary>Indicates that the destination key has been activated.</summary>
    Activated = 4,
    /// <summary>Indicates that the application has confirmed its committed cutover.</summary>
    ApplicationCutoverConfirmed = 5,
    /// <summary>Indicates that the original key has been retired.</summary>
    SourceRetired = 6,
    /// <summary>Indicates that the original key was deleted after retention checks.</summary>
    SourceDeleted = 7
}
