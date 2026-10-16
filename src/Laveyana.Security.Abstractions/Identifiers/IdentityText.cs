using System.Globalization;

namespace Laveyana.Security.Abstractions.Identifiers;

/// <summary>
/// Implements the deliberately narrow, culture-independent identity text grammar.
/// </summary>
internal static class IdentityText
{
    internal const int MaximumNameLength = 128;
    internal const int MaximumTokenLength = 128;

    /// <summary>
    /// Checks the canonical textual form of a non-empty UUID.
    /// </summary>
    internal static bool TryReadGuid(string? text, out Guid value)
    {
        if (text is not null &&
            text.Length == 36 &&
            Guid.TryParseExact(text, "D", out value) &&
            value != Guid.Empty &&
            string.Equals(value.ToString("D", CultureInfo.InvariantCulture), text, StringComparison.Ordinal))
        {
            return true;
        }

        value = default;
        return false;
    }

    /// <summary>
    /// Accepts only portable application names with exact ordinal case semantics.
    /// </summary>
    internal static bool IsName(string? text)
    {
        if (string.IsNullOrEmpty(text) || text.Length > MaximumNameLength || !IsAsciiLetter(text[0]))
        {
            return false;
        }

        foreach (char character in text.AsSpan(1))
        {
            if (!IsAsciiLetter(character) && !IsAsciiDigit(character) && character is not ('.' or '_' or '-'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Accepts lowercase, non-empty, separator-delimited stable catalog tokens.
    /// </summary>
    internal static bool IsToken(string? text)
    {
        if (string.IsNullOrEmpty(text) || text.Length > MaximumTokenLength || !IsAsciiLower(text[0]))
        {
            return false;
        }

        bool previousSeparator = false;
        foreach (char character in text.AsSpan(1))
        {
            bool separator = character is '.' or '_' or '-';
            if (separator && previousSeparator)
            {
                return false;
            }

            if (!IsAsciiLower(character) && !IsAsciiDigit(character) && !separator)
            {
                return false;
            }

            previousSeparator = separator;
        }

        return !previousSeparator;
    }

    /// <summary>
    /// Checks ASCII letters without Unicode case mapping or culture dependencies.
    /// </summary>
    private static bool IsAsciiLetter(char character) =>
        character is >= 'a' and <= 'z' or >= 'A' and <= 'Z';

    /// <summary>
    /// Checks ASCII lowercase letters.
    /// </summary>
    private static bool IsAsciiLower(char character) => character is >= 'a' and <= 'z';

    /// <summary>
    /// Checks ASCII decimal digits.
    /// </summary>
    private static bool IsAsciiDigit(char character) => character is >= '0' and <= '9';
}
