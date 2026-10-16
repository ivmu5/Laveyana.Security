using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Rotation;

/// <summary>
/// A version-fenced instruction from an authoritative application schedule.
/// Each new active version needs its own persisted assignment with a trusted UTC anchor.
/// </summary>
public readonly record struct RotationAssignment
{
    /// <summary>Creates an explicit assignment for one expected active version.</summary>
    public RotationAssignment(LogicalKeyHandle handle, KeyVersion expectedActiveVersion,
        DateTimeOffset lastActivatedUtc, RotationPolicy policy)
    {
        if (!handle.IsDefined || !expectedActiveVersion.IsDefined)
        {
            throw new ArgumentException("Defined key and expected version are required.");
        }

        _ = policy.DueAtUtc(lastActivatedUtc);
        Handle = handle;
        ExpectedActiveVersion = expectedActiveVersion;
        LastActivatedUtc = lastActivatedUtc;
        Policy = policy;
    }

    /// <summary>Gets the stable key identity.</summary>
    public LogicalKeyHandle Handle { get; }

    /// <summary>Gets the only active version permitted to be replaced by this instruction.</summary>
    public KeyVersion ExpectedActiveVersion { get; }

    /// <summary>Gets the caller-authenticated activation instant.</summary>
    public DateTimeOffset LastActivatedUtc { get; }

    /// <summary>Gets the rotation interval.</summary>
    public RotationPolicy Policy { get; }

    /// <summary>Gets the deadline after which policy-driven rotation is due.</summary>
    public DateTimeOffset DueAtUtc => Policy.DueAtUtc(LastActivatedUtc);

    /// <summary>Hides the key identity in diagnostic strings.</summary>
    public override string ToString() => nameof(RotationAssignment);
}
