namespace Laveyana.Security.Abstractions.Identifiers;

/// <summary>
/// A persistent secret identity containing the stable provider and secret identifiers.
/// </summary>
public readonly record struct SecretReference
{
    /// <summary>
    /// Constructs a secret reference with defined stable identifiers.
    /// </summary>
    /// <exception cref="ArgumentException">A component is uninitialized.</exception>
    public SecretReference(ProviderId providerId, SecretId secretId)
    {
        if (!providerId.IsDefined || !secretId.IsDefined)
        {
            throw new ArgumentException("Secret reference components must be defined.");
        }

        ProviderId = providerId;
        SecretId = secretId;
    }

    /// <summary>Gets the immutable persistent provider identity.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Gets the immutable secret identity.</summary>
    public SecretId SecretId { get; }

    /// <summary>Gets whether all components contain defined values.</summary>
    public bool IsDefined => ProviderId.IsDefined && SecretId.IsDefined;

    /// <summary>
    /// Parses the canonical provider-UUID/secret-UUID representation.
    /// </summary>
    /// <exception cref="FormatException">The input is not a canonical secret reference.</exception>
    public static SecretReference Parse(string text) =>
        TryParse(text, out SecretReference result) ? result : throw new FormatException("Invalid SecretReference.");

    /// <summary>
    /// Tries to parse a stable reference with no runtime provider aliases.
    /// </summary>
    public static bool TryParse(string? text, out SecretReference result)
    {
        if (text is not null && text.Length == 73)
        {
            string[] segments = text.Split('/');
            if (segments.Length == 2 &&
                ProviderId.TryParse(segments[0], out ProviderId providerId) &&
                SecretId.TryParse(segments[1], out SecretId secretId))
            {
                result = new SecretReference(providerId, secretId);
                return true;
            }
        }

        result = default;
        return false;
    }

    /// <summary>Formats the explicitly defined persistent wire representation.</summary>
    public override string ToString() => IsDefined
        ? $"{ProviderId}/{SecretId}"
        : throw new InvalidOperationException("An undefined SecretReference cannot be formatted.");
}
