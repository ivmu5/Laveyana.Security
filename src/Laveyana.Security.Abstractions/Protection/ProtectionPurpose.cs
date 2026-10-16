namespace Laveyana.Security.Abstractions.Protection;

/// <summary>Cryptographically separated envelope purposes. Never reuse a domain for another purpose.</summary>
public enum ProtectionPurpose
{
    /// <summary>Indicates that the protection purpose has not been specified.</summary>
    Unspecified = 0,
    /// <summary>Identifies protected key metadata.</summary>
    Metadata = 1,
    /// <summary>Identifies protected cryptographic key material.</summary>
    KeyMaterial = 2
}
