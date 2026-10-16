using System.Globalization;

namespace Laveyana.Security.Abstractions.Protection;

/// <summary>Stable, persisted protector identity and positive protection-key generation.</summary>
/// <remarks>This is not a runtime alias and does not expose a root protection key.</remarks>
public readonly record struct ProtectorReference
{
    /// <summary>Constructs a stable reference with a portable identifier and positive generation.</summary>
    public ProtectorReference(string id, int version)
    {
        if (!IsValidId(id))
        {
            throw new ArgumentException("Protector id must be 1-128 portable ASCII name characters.", nameof(id));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(version);
        Id = id;
        Version = version;
    }

    /// <summary>Gets the stable protector identifier.</summary>
    public string? Id { get; }

    /// <summary>Gets the positive protector generation, not a key material version.</summary>
    public int Version { get; }

    /// <summary>Gets whether both identity components are initialized.</summary>
    public bool IsDefined => Id is not null && Version > 0;

    /// <summary>Gets the canonical persistent reference.</summary>
    public override string ToString() => IsDefined
        ? $"{Id}/{Version.ToString(CultureInfo.InvariantCulture)}"
        : throw new InvalidOperationException("An undefined protector reference cannot be formatted.");

    /// <summary>Parses an exact portable reference with no normalization or alias resolution.</summary>
    public static bool TryParse(string? text, out ProtectorReference reference)
    {
        reference = default;
        if (text is null)
        {
            return false;
        }

        int separator = text.IndexOf('/');
        if (separator <= 0 || separator >= text.Length - 1 || text.LastIndexOf('/') != separator)
        {
            return false;
        }

        string id = text[..separator];
        string versionText = text[(separator + 1)..];
        if (!IsValidId(id) || versionText.Length is < 1 or > 10 ||
            versionText[0] is < '1' or > '9' ||
            !int.TryParse(versionText, NumberStyles.None, CultureInfo.InvariantCulture, out int version) ||
            version <= 0 ||
            !string.Equals(version.ToString(CultureInfo.InvariantCulture), versionText, StringComparison.Ordinal))
        {
            return false;
        }

        reference = new ProtectorReference(id, version);
        return true;
    }

    /// <summary>Parses a canonical protector reference or throws.</summary>
    public static ProtectorReference Parse(string text) => TryParse(text, out ProtectorReference reference)
        ? reference : throw new FormatException("Invalid protector reference.");

    private static bool IsValidId(string? id)
    {
        if (id is null || id.Length is < 1 or > 128 || !IsAsciiLetter(id[0]))
        {
            return false;
        }

        foreach (char character in id)
        {
            if (!IsAsciiLetter(character) && character is not (>= '0' and <= '9') and not '.' and not '_' and not '-')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAsciiLetter(char character) => character is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z');
}
