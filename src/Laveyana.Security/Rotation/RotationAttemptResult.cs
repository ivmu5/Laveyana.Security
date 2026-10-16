using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Rotation;

/// <summary>Non-secret execution outcome; never conveys whether unknown commits succeeded.</summary>
public sealed record RotationAttemptResult
{
    /// <summary>Creates a validated result with an optional committed descriptor.</summary>
    public RotationAttemptResult(RotationAttemptStatus status, KeyDescriptor? descriptor = null)
    {
        if (!Enum.IsDefined(status) || (status == RotationAttemptStatus.Rotated) != (descriptor is not null))
        {
            throw new ArgumentException("The result and committed descriptor disagree.");
        }

        Status = status;
        Descriptor = descriptor;
    }

    /// <summary>Gets the definite outcome.</summary>
    public RotationAttemptStatus Status { get; }

    /// <summary>Gets the committed descriptor only after successful rotation.</summary>
    public KeyDescriptor? Descriptor { get; }

    /// <summary>Redacts metadata from incidental logs.</summary>
    public override string ToString() => nameof(RotationAttemptResult);
}
