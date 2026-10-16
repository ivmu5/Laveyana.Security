namespace Laveyana.Security.Abstractions.Identifiers;

/// <summary>
/// Represents a runtime provider lookup alias; it is not a persistent cryptographic identifier.
/// Names use ordinal, case-sensitive equality and are never silently normalized.
/// </summary>
public readonly record struct ProviderAlias
{
    private readonly string? _value;

    /// <summary>
    /// Constructs a non-empty, portable name: ASCII letter followed by at most 127
    /// ASCII letters, digits, dots, underscores or hyphens.
    /// </summary>
    /// <exception cref="ArgumentException">The name does not follow the portable-name grammar.</exception>
    public ProviderAlias(string value)
    {
        if (!IdentityText.IsName(value))
        {
            throw new ArgumentException("Name must be 1-128 characters, start with an ASCII letter, and contain only ASCII letters, digits, '.', '_' or '-'.", nameof(value));
        }

        _value = value;
    }

    /// <summary>
    /// Gets the original validated name without case folding or trimming.
    /// </summary>
    /// <exception cref="InvalidOperationException">This is an uninitialized name.</exception>
    public string Value => _value ?? throw new InvalidOperationException("Undefined ProviderAlias.");

    /// <summary>
    /// Gets whether this struct contains a valid name.
    /// </summary>
    public bool IsDefined => _value is not null;

    /// <summary>
    /// Parses a portable name.
    /// </summary>
    /// <exception cref="FormatException">The input is not a portable name.</exception>
    public static ProviderAlias Parse(string text) =>
        TryParse(text, out ProviderAlias result) ? result : throw new FormatException("Invalid ProviderAlias.");

    /// <summary>
    /// Tries to parse a portable name without normalizing its case.
    /// </summary>
    public static bool TryParse(string? text, out ProviderAlias result)
    {
        if (IdentityText.IsName(text))
        {
            result = new ProviderAlias(text!);
            return true;
        }

        result = default;
        return false;
    }

    /// <summary>
    /// Returns the unmodified validated alias text.
    /// </summary>
    public override string ToString() => Value;
}
