namespace Laveyana.Security.Abstractions.Rollback;

/// <summary>Stable identity of exactly one authority mutation, including all of its arguments.</summary>
/// <remarks>
/// Create a fresh random identifier for each new semantic request, durably record it with the
/// exact immutable arguments before sending, and reuse it only when retrying that same request.
/// An identifier is never a substitute for an authenticated caller or authority authorization.
/// </remarks>
public sealed class RollbackRequestId : IEquatable<RollbackRequestId>
{
    /// <summary>Creates a nonempty request identity.</summary>
    public RollbackRequestId(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("A nonempty authority request identity is required.", nameof(value));
        }

        Value = value;
    }

    /// <summary>The unique value shared by retries of the same authority operation.</summary>
    public Guid Value { get; }

    /// <summary>Checks exact request identity equality.</summary>
    public bool Equals(RollbackRequestId? other) => other is not null && Value == other.Value;

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is RollbackRequestId other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value.GetHashCode();

    /// <summary>Does not expose request identifiers in generic logs.</summary>
    public override string ToString() => nameof(RollbackRequestId);
}
