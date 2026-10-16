using System.Globalization;

namespace Laveyana.Security.Abstractions.Storage;

/// <summary>A positive optimistic-concurrency revision within one authoritative key history.</summary>
public readonly record struct KeyStoreRevision : IComparable<KeyStoreRevision>
{
    /// <summary>Creates a positive revision.</summary>
    public KeyStoreRevision(long value)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value);
        Value = value;
    }

    /// <summary>Gets the positive revision ordinal.</summary>
    public long Value { get; }

    /// <summary>Gets whether this revision was initialized.</summary>
    public bool IsDefined => Value > 0;

    /// <summary>Compares revisions within the same aggregate only.</summary>
    public int CompareTo(KeyStoreRevision other) => Value.CompareTo(other.Value);

    /// <summary>Formats a defined revision.</summary>
    public override string ToString() => IsDefined
        ? Value.ToString(CultureInfo.InvariantCulture)
        : throw new InvalidOperationException("Undefined key store revision.");
}
