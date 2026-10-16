using System.Globalization;

namespace Laveyana.Security.Abstractions.Identifiers;

/// <summary>
/// Identifies a persistent provider identity using a non-empty UUID independent of CLR type names.
/// The default struct value is invalid and must not cross a contract boundary.
/// </summary>
public readonly record struct ProviderId
{
    /// <summary>
    /// Creates a validated identifier from a non-empty UUID.
    /// </summary>
    /// <exception cref="ArgumentException">The UUID is empty.</exception>
    public ProviderId(Guid value)
    {
        ArgumentOutOfRangeException.ThrowIfEqual(value, Guid.Empty);
        Value = value;
    }

    /// <summary>
    /// Gets the raw UUID without implying a provider or storage format.
    /// </summary>
    public Guid Value { get; }

    /// <summary>
    /// Gets whether this struct contains a valid identifier.
    /// </summary>
    public bool IsDefined => Value != Guid.Empty;

    /// <summary>
    /// Creates an identifier for a new identity; persist it before referencing it.
    /// </summary>
    public static ProviderId New() => new(Guid.NewGuid());

    /// <summary>
    /// Parses a canonical lowercase UUID in the 8-4-4-4-12 format.
    /// </summary>
    /// <exception cref="FormatException">The input is not a canonical non-empty UUID.</exception>
    public static ProviderId Parse(string text) =>
        TryParse(text, out ProviderId result) ? result : throw new FormatException("Invalid ProviderId.");

    /// <summary>
    /// Tries to parse a canonical lowercase UUID; never normalizes malformed text.
    /// </summary>
    public static bool TryParse(string? text, out ProviderId result)
    {
        if (IdentityText.TryReadGuid(text, out Guid value))
        {
            result = new ProviderId(value);
            return true;
        }

        result = default;
        return false;
    }

    /// <summary>
    /// Returns the defined canonical lowercase UUID representation.
    /// </summary>
    /// <exception cref="InvalidOperationException">This is an uninitialized identifier.</exception>
    public override string ToString() => IsDefined
        ? Value.ToString("D", CultureInfo.InvariantCulture)
        : throw new InvalidOperationException("An undefined ProviderId cannot be formatted.");
}
