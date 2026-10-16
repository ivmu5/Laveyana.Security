namespace Laveyana.Security.Abstractions.Identifiers;

/// <summary>
/// Defines stable operation capabilities; declaring one does not authorize its use by itself.
/// Effective access also requires applicable key and algorithm policy.
/// </summary>
public static class WellKnownCapabilities
{
    /// <summary>Encrypt with key material.</summary>
    public static CapabilityId Encrypt { get; } = new("encrypt");

    /// <summary>Decrypt an existing payload.</summary>
    public static CapabilityId Decrypt { get; } = new("decrypt");

    /// <summary>Generate a message authentication code.</summary>
    public static CapabilityId Mac { get; } = new("mac");

    /// <summary>Verify a message authentication code.</summary>
    public static CapabilityId VerifyMac { get; } = new("verify-mac");

    /// <summary>Derive cryptographic material.</summary>
    public static CapabilityId Derive { get; } = new("derive");

    /// <summary>Generate a digital signature.</summary>
    public static CapabilityId Sign { get; } = new("sign");

    /// <summary>Verify an existing digital signature.</summary>
    public static CapabilityId VerifySignature { get; } = new("verify-signature");

    /// <summary>Derive a shared key through key agreement and a required KDF.</summary>
    public static CapabilityId KeyAgreement { get; } = new("key-agreement");

    /// <summary>Temporarily open material to an authorized scoped operation.</summary>
    public static CapabilityId OpenMaterial { get; } = new("open-material");

    /// <summary>Export material when explicitly authorized by policy and provider.</summary>
    public static CapabilityId ExportMaterial { get; } = new("export-material");
}
