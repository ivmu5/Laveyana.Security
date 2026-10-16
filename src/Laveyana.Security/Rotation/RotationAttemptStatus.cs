using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Rotation;

/// <summary>Outcomes that are safe to report without exposing key material.</summary>
public enum RotationAttemptStatus
{
    /// <summary>Deadline has not been reached.</summary>
    NotDue = 1,
    /// <summary>The scheduled version is not the active version any more.</summary>
    VersionChanged = 2,
    /// <summary>The authoritative transaction committed a new version.</summary>
    Rotated = 3,
    /// <summary>A concurrent transaction prevented this attempt from committing.</summary>
    Conflict = 4
}
