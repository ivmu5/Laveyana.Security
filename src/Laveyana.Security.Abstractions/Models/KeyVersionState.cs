namespace Laveyana.Security.Abstractions.Models;

/// <summary>
/// Describes the state of one exact key material version.
/// Discarded pending material is represented by Deleted, not a separate state.
/// Numeric values are not a persistent interchange representation.
/// </summary>
public enum KeyVersionState
{
    /// <summary>An uninitialized, invalid state.</summary>
    Unspecified = 0,

    /// <summary>A reserved version that has never been activated.</summary>
    Pending = 1,

    /// <summary>The current active version.</summary>
    Active = 2,

    /// <summary>A historical version still permitted for selected operations.</summary>
    Retired = 3,

    /// <summary>A permanently inactive/deleted version identity.</summary>
    Deleted = 4,
}
