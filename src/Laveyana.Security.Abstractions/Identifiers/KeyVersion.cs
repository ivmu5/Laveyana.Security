using System.Globalization;

namespace Laveyana.Security.Abstractions.Identifiers;

/// <summary>
/// Identifies a positive, monotonically reserved key material version within a KeyId.
/// The reservation and non-reuse guarantee belong to the authoritative store.
/// </summary>
public readonly record struct KeyVersion : IComparable<KeyVersion>
{
    /// <summary>
    /// Constructs a positive key version.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The version is not positive.</exception>
    public KeyVersion(long value)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value);
        Value = value;
    }

    /// <summary>
    /// Gets the strictly positive version ordinal.
    /// </summary>
    public long Value { get; }

    /// <summary>
    /// Gets whether the version is valid rather than an uninitialized struct.
    /// </summary>
    public bool IsDefined => Value > 0;

    /// <summary>
    /// Parses a canonical base-ten positive integer with no leading zeros.
    /// </summary>
    /// <exception cref="FormatException">The input is not a canonical version.</exception>
    public static KeyVersion Parse(string text) =>
        TryParse(text, out KeyVersion version) ? version : throw new FormatException("Invalid KeyVersion.");

    /// <summary>
    /// Tries to parse a canonical positive version using invariant culture.
    /// </summary>
    public static bool TryParse(string? text, out KeyVersion result)
    {
        if (text is not null &&
            text.Length is > 0 and <= 19 &&
            text[0] is >= '1' and <= '9' &&
            long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long value) &&
            value > 0 &&
            string.Equals(value.ToString(CultureInfo.InvariantCulture), text, StringComparison.Ordinal))
        {
            result = new KeyVersion(value);
            return true;
        }

        result = default;
        return false;
    }

    /// <summary>
    /// Compares version numbers without implying their ordering across different keys.
    /// </summary>
    public int CompareTo(KeyVersion other) => Value.CompareTo(other.Value);

    /// <summary>
    /// Formats a defined version as a canonical invariant decimal integer.
    /// </summary>
    public override string ToString() => IsDefined
        ? Value.ToString(CultureInfo.InvariantCulture)
        : throw new InvalidOperationException("An undefined KeyVersion cannot be formatted.");
}
