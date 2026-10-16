namespace Laveyana.Security.Abstractions.Models;

/// <summary>
/// Describes the domain state of a logical key generation.
/// Numeric values are not a persistent interchange representation.
/// </summary>
public enum LogicalKeyState
{
    /// <summary>An uninitialized, invalid state.</summary>
    Unspecified = 0,

    /// <summary>Exactly one version is active for forward use.</summary>
    Active = 1,

    /// <summary>The generation is kept for permitted historical operations.</summary>
    Retired = 2,

    /// <summary>The generation has been logically deleted.</summary>
    Deleted = 3,
}
