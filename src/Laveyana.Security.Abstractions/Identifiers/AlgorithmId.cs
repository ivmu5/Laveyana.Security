namespace Laveyana.Security.Abstractions.Identifiers;

/// <summary>
/// Identifies a cryptographic algorithm with an explicit stable token, never a CLR name or enum ordinal.
/// </summary>
public readonly record struct AlgorithmId
{
    private readonly string? _value;

    /// <summary>
    /// Constructs a lowercase ASCII token with internal single '.', '_' or '-' separators.
    /// </summary>
    /// <exception cref="ArgumentException">The token is not canonical.</exception>
    public AlgorithmId(string value)
    {
        if (!IdentityText.IsToken(value))
        {
            throw new ArgumentException("Token must be 1-128 lowercase ASCII characters, start with a letter and contain no leading, trailing or consecutive separators.", nameof(value));
        }

        _value = value;
    }

    /// <summary>Gets the validated stable text.</summary>
    /// <exception cref="InvalidOperationException">This is an uninitialized token.</exception>
    public string Value => _value ?? throw new InvalidOperationException("Undefined AlgorithmId.");

    /// <summary>Gets whether the token is initialized.</summary>
    public bool IsDefined => _value is not null;

    /// <summary>
    /// Parses an exact token without culture-dependent normalization.
    /// </summary>
    /// <exception cref="FormatException">The token is invalid.</exception>
    public static AlgorithmId Parse(string text) =>
        TryParse(text, out AlgorithmId result) ? result : throw new FormatException("Invalid AlgorithmId.");

    /// <summary>Tries to parse an exact lowercase token.</summary>
    public static bool TryParse(string? text, out AlgorithmId result)
    {
        if (IdentityText.IsToken(text))
        {
            result = new AlgorithmId(text!);
            return true;
        }

        result = default;
        return false;
    }

    /// <summary>Formats the explicit stable token.</summary>
    public override string ToString() => Value;
}
