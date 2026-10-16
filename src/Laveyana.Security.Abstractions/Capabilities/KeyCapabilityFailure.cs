namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>Generic metadata resolution failures; no key identity is included in diagnostics.</summary>
public enum KeyCapabilityFailure
{
    /// <summary>No failure.</summary>
    None = 0,

    /// <summary>The requested logical key or exact version does not exist.</summary>
    NotFound = 1,

    /// <summary>One or more metadata snapshots are inconsistent with the requested identity.</summary>
    IdentityMismatch = 2,

    /// <summary>The key kind is incompatible with the typed capability view.</summary>
    KindMismatch = 3,

    /// <summary>The requested lifecycle state is not permitted.</summary>
    StateRejected = 4,

    /// <summary>The exact version does not declare the requested capability.</summary>
    CapabilityMissing = 5,
}
