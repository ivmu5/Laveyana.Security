namespace Laveyana.Security.Abstractions.Models;

/// <summary>
/// Describes the type of key material without implying operational permissions.
/// Numeric values are not a persistent interchange representation.
/// </summary>
public enum KeyKind
{
    /// <summary>The uninitialized, invalid kind.</summary>
    Unspecified = 0,

    /// <summary>Symmetric shared-secret key material.</summary>
    Symmetric = 1,

    /// <summary>Asymmetric private key material, which may be non-exportable.</summary>
    AsymmetricPrivate = 2,

    /// <summary>Asymmetric public-only key material.</summary>
    AsymmetricPublic = 3,
}
