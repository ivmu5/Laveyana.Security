namespace Laveyana.Security.Lifecycle;

/// <summary>
/// An immutable deletion guard supplied by an authoritative lifecycle snapshot.
/// A force-delete path explicitly ignores this guard and is always destructive.
/// </summary>
internal readonly record struct KeyRetentionConstraint
{
    /// <summary>Creates a retention constraint with an optional UTC deadline and hold.</summary>
    public KeyRetentionConstraint(DateTimeOffset? retainUntilUtc, bool isOnHold = false)
    {
        if (retainUntilUtc.HasValue && retainUntilUtc.Value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Retention deadline must be UTC.", nameof(retainUntilUtc));
        }

        RetainUntilUtc = retainUntilUtc;
        IsOnHold = isOnHold;
    }

    /// <summary>Gets the earliest instant at which normal deletion is allowed.</summary>
    public DateTimeOffset? RetainUntilUtc { get; }

    /// <summary>Gets whether an indefinite deletion hold is in effect.</summary>
    public bool IsOnHold { get; }

    /// <summary>Tests the constraint against a caller-supplied UTC clock.</summary>
    public bool AllowsDeletion(DateTimeOffset nowUtc)
    {
        if (nowUtc.Offset != TimeSpan.Zero || nowUtc == default)
        {
            throw new ArgumentException("Deletion time must be a defined UTC instant.", nameof(nowUtc));
        }

        return !IsOnHold && (!RetainUntilUtc.HasValue || nowUtc >= RetainUntilUtc.Value);
    }
}
