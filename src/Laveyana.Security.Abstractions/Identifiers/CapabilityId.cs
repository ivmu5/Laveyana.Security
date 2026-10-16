namespace Laveyana.Security.Abstractions.Identifiers;

/// <summary>
/// Identifies a provider or key capability with an explicit stable token, never a CLR name or enum ordinal.
/// </summary>
public readonly record struct CapabilityId
{
    private readonly string? _value;

    /// <summary>
    /// Constructs a lowercase ASCII token with internal single '.', '_' or '-' separators.
    /// </summary>
    /// <exception cref="ArgumentException">The token is not canonical.</exception>
    public CapabilityId(string value)
    {
        if (!IdentityText.IsToken(value))
        {
            throw new ArgumentException("Token must be 1-128 lowercase ASCII characters, start with a letter and contain no leading, trailing or consecutive separators.", nameof(value));
        }

        _value = value;
    }

    /// <summary>Gets the validated stable text.</summary>
    /// <exception cref="InvalidOperationException">This is an uninitialized token.</exception>
    public string Value => _value ?? throw new InvalidOperationException("Undefined CapabilityId.");

    /// <summary>Gets whether the token is initialized.</summary>
    public bool IsDefined => _value is not null;

    /// <summary>
    /// Parses an exact token without culture-dependent normalization.
    /// </summary>
    /// <exception cref="FormatException">The token is invalid.</exception>
    public static CapabilityId Parse(string text) =>
        TryParse(text, out CapabilityId result) ? result : throw new FormatException("Invalid CapabilityId.");

    /// <summary>Tries to parse an exact lowercase token.</summary>
    public static bool TryParse(string? text, out CapabilityId result)
    {
        if (IdentityText.IsToken(text))
        {
            result = new CapabilityId(text!);
            return true;
        }

        result = default;
        return false;
    }

    /// <summary>Formats the explicit stable token.</summary>
    public override string ToString() => Value;
}
