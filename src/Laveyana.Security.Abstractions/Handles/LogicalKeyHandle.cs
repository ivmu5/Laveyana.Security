using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Handles;

/// <summary>
/// Identifies a logical key generation, not a material version. Forward operations
/// must resolve the current Active version for every invocation.
/// </summary>
public readonly record struct LogicalKeyHandle
{
    /// <summary>Creates a logical handle from stable identities, never a runtime alias.</summary>
    public LogicalKeyHandle(ProviderId providerId, KeyId keyId)
    {
        if (!providerId.IsDefined || !keyId.IsDefined)
        {
            throw new ArgumentException("A logical handle requires defined provider and key identities.");
        }

        ProviderId = providerId;
        KeyId = keyId;
    }

    /// <summary>Gets the persistent provider identity.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Gets the persistent logical key identity.</summary>
    public KeyId KeyId { get; }

    /// <summary>Gets whether this handle is initialized.</summary>
    public bool IsDefined => ProviderId.IsDefined && KeyId.IsDefined;

    /// <summary>Creates an immutable exact-version handle for an explicitly selected version.</summary>
    public ExactKeyHandle AtVersion(KeyVersion version)
    {
        if (!IsDefined || !version.IsDefined)
        {
            throw new InvalidOperationException("A defined logical handle and version are required.");
        }

        return new ExactKeyHandle(new KeyReference(ProviderId, KeyId, version));
    }

    /// <summary>Redacts identifiers in incidental logs.</summary>
    public override string ToString() => "LogicalKeyHandle";
}
