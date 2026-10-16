namespace Laveyana.Security.Abstractions.Identifiers;

/// <summary>
/// A persistent exact material identity: provider/key/version, never a runtime alias.
/// </summary>
public readonly record struct KeyReference
{
    /// <summary>
    /// Constructs an exact key reference from three defined stable identities.
    /// </summary>
    /// <exception cref="ArgumentException">Any component is uninitialized.</exception>
    public KeyReference(ProviderId providerId, KeyId keyId, KeyVersion version)
    {
        if (!providerId.IsDefined || !keyId.IsDefined || !version.IsDefined)
        {
            throw new ArgumentException("All key reference components must be defined.");
        }

        ProviderId = providerId;
        KeyId = keyId;
        Version = version;
    }

    /// <summary>Gets the immutable persistent provider identity.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Gets the immutable logical key generation identity.</summary>
    public KeyId KeyId { get; }

    /// <summary>Gets the exact material version.</summary>
    public KeyVersion Version { get; }

    /// <summary>Gets whether all components contain defined values.</summary>
    public bool IsDefined => ProviderId.IsDefined && KeyId.IsDefined && Version.IsDefined;

    /// <summary>
    /// Parses the canonical provider-UUID/key-UUID/positive-version representation.
    /// </summary>
    /// <exception cref="FormatException">The input is not a canonical exact reference.</exception>
    public static KeyReference Parse(string text) =>
        TryParse(text, out KeyReference result) ? result : throw new FormatException("Invalid KeyReference.");

    /// <summary>
    /// Tries to parse a stable exact reference with no aliases, padding or extra segments.
    /// </summary>
    public static bool TryParse(string? text, out KeyReference result)
    {
        if (text is not null && text.Length is >= 75 and <= 93)
        {
            string[] segments = text.Split('/');
            if (segments.Length == 3 &&
                ProviderId.TryParse(segments[0], out ProviderId providerId) &&
                KeyId.TryParse(segments[1], out KeyId keyId) &&
                KeyVersion.TryParse(segments[2], out KeyVersion version))
            {
                result = new KeyReference(providerId, keyId, version);
                return true;
            }
        }

        result = default;
        return false;
    }

    /// <summary>
    /// Formats the explicitly defined persistent wire representation.
    /// </summary>
    public override string ToString() => IsDefined
        ? $"{ProviderId}/{KeyId}/{Version}"
        : throw new InvalidOperationException("An undefined KeyReference cannot be formatted.");
}
