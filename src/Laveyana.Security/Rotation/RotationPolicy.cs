namespace Laveyana.Security.Rotation;

/// <summary>
/// An application-selected rotation interval. The library does not infer a creation
/// timestamp from key version numbers or unauthenticated local filesystem timestamps.
/// </summary>
public readonly record struct RotationPolicy
{
    /// <summary>Creates a bounded strictly positive interval.</summary>
    public RotationPolicy(TimeSpan interval)
    {
        if (interval <= TimeSpan.Zero || interval > TimeSpan.FromDays(3650))
        {
            throw new ArgumentOutOfRangeException(nameof(interval));
        }

        Interval = interval;
    }

    /// <summary>Gets the configured duration after last trusted activation.</summary>
    public TimeSpan Interval { get; }

    /// <summary>Computes the next due instant from a trusted application-supplied UTC anchor.</summary>
    public DateTimeOffset DueAtUtc(DateTimeOffset lastActivatedUtc)
    {
        if (lastActivatedUtc == default || lastActivatedUtc.Offset != TimeSpan.Zero || Interval <= TimeSpan.Zero)
        {
            throw new ArgumentException("A valid policy and UTC activation time are required.");
        }

        return lastActivatedUtc.Add(Interval);
    }
}
