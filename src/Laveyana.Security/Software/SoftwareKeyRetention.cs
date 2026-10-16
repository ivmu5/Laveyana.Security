using Laveyana.Security.Lifecycle;

namespace Laveyana.Security.Software;

/// <summary>Immutable deletion hold or UTC deadline applied when new key material is created.</summary>
public readonly record struct SoftwareKeyRetention
{
    /// <summary>Constructs a new per-version retention constraint.</summary>
    public SoftwareKeyRetention(DateTimeOffset? retainUntilUtc, bool isOnHold = false)
    {
        if (retainUntilUtc.HasValue && (retainUntilUtc.Value.Offset != TimeSpan.Zero ||
            retainUntilUtc.Value.UtcTicks == 0))
        {
            throw new ArgumentException("Retention deadline must use UTC.", nameof(retainUntilUtc));
        }

        RetainUntilUtc = retainUntilUtc;
        IsOnHold = isOnHold;
    }

    /// <summary>Gets the first UTC instant at which normal deletion is allowed.</summary>
    public DateTimeOffset? RetainUntilUtc { get; }

    /// <summary>Gets whether a separate indefinite deletion hold is active.</summary>
    public bool IsOnHold { get; }

    internal KeyRetentionConstraint ToConstraint() => new(RetainUntilUtc, IsOnHold);
}
