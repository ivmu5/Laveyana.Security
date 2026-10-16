using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Handles;

/// <summary>
/// Pins one exact material version permanently. Rotation cannot change the reference.
/// </summary>
public readonly record struct ExactKeyHandle
{
    /// <summary>Creates an exact handle from a validated persistent reference.</summary>
    public ExactKeyHandle(KeyReference reference)
    {
        if (!reference.IsDefined)
        {
            throw new ArgumentException("An exact handle requires a defined reference.", nameof(reference));
        }

        Reference = reference;
    }

    /// <summary>Gets the exact material reference, including version.</summary>
    public KeyReference Reference { get; }

    /// <summary>Gets whether this handle is initialized.</summary>
    public bool IsDefined => Reference.IsDefined;

    /// <summary>Gets the owning logical generation without resolving Active.</summary>
    public LogicalKeyHandle Logical => IsDefined
        ? new LogicalKeyHandle(Reference.ProviderId, Reference.KeyId)
        : throw new InvalidOperationException("An undefined exact handle has no logical identity.");

    /// <summary>Redacts identifiers in incidental logs.</summary>
    public override string ToString() => "ExactKeyHandle";
}
