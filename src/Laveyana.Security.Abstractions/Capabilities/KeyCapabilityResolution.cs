using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>
/// A metadata-only exact-version selection for one requested operation. It is NOT
/// a cryptographic operation, an authorization token or a concurrency reservation.
/// Backends must independently check policy, capability and state at dispatch.
/// </summary>
public sealed class KeyCapabilityResolution
{
    internal KeyCapabilityResolution(ExactKeyHandle exactHandle, AlgorithmId algorithm, CapabilityId capability)
    {
        ExactHandle = exactHandle;
        Algorithm = algorithm;
        Capability = capability;
    }

    /// <summary>Gets the exact version observed during metadata preflight.</summary>
    public ExactKeyHandle ExactHandle { get; }

    /// <summary>Gets that version's algorithm identity, not an algorithm guarantee.</summary>
    public AlgorithmId Algorithm { get; }

    /// <summary>Gets the requested declared capability, not an authorization grant.</summary>
    public CapabilityId Capability { get; }

    /// <summary>Redacts key identity and operation details from incidental logging.</summary>
    public override string ToString() => "KeyCapabilityResolution";
}
