using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Models;

/// <summary>
/// An immutable snapshot of a logical key generation without exposed key material.
/// The provider and key IDs, not the optional name, determine identity.
/// </summary>
public sealed record KeyDescriptor
{
    /// <summary>
    /// Constructs a validated logical metadata snapshot; only Active may expose an active version.
    /// </summary>
    /// <exception cref="ArgumentException">Identifiers, kind, state or the active-version invariant is invalid.</exception>
    public KeyDescriptor(
        ProviderId providerId,
        KeyId keyId,
        KeyName? name,
        KeyKind kind,
        LogicalKeyState state,
        KeyVersion? activeVersion)
    {
        if (!providerId.IsDefined || !keyId.IsDefined || (name.HasValue && !name.Value.IsDefined))
        {
            throw new ArgumentException("Key descriptor identities must be defined.");
        }

        if (!Enum.IsDefined(kind) || kind == KeyKind.Unspecified ||
            !Enum.IsDefined(state) || state == LogicalKeyState.Unspecified)
        {
            throw new ArgumentException("Key kind and logical state must be known.");
        }

        if ((state == LogicalKeyState.Active) != activeVersion.HasValue ||
            (activeVersion.HasValue && !activeVersion.Value.IsDefined))
        {
            throw new ArgumentException("Exactly an Active logical key must provide its defined active version.");
        }

        ProviderId = providerId;
        KeyId = keyId;
        Name = name;
        Kind = kind;
        State = state;
        ActiveVersion = activeVersion;
    }

    /// <summary>Gets the persistent provider identity.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Gets the immutable logical generation identity.</summary>
    public KeyId KeyId { get; }

    /// <summary>Gets an optional non-persistent application name.</summary>
    public KeyName? Name { get; }

    /// <summary>Gets the key material category, independent of capabilities.</summary>
    public KeyKind Kind { get; }

    /// <summary>Gets the logical state captured by this snapshot.</summary>
    public LogicalKeyState State { get; }

    /// <summary>Gets the active material version, if the logical state is Active.</summary>
    public KeyVersion? ActiveVersion { get; }

    /// <summary>
    /// Returns a redacted type label rather than emitting identity metadata to logs.
    /// </summary>
    public override string ToString() => "KeyDescriptor";
}
