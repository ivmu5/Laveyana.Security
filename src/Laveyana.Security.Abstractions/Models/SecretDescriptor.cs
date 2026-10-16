using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Models;

/// <summary>
/// Immutable read-oriented secret metadata, without material or a universal version.
/// Capability declarations are hints only, not authorization to access bytes.
/// </summary>
public sealed record SecretDescriptor
{
    /// <summary>Creates a descriptor; default capabilities deny material access.</summary>
    public SecretDescriptor(
        SecretReference reference,
        bool canOpenMaterial = false,
        bool canExportMaterial = false)
    {
        if (!reference.IsDefined)
        {
            throw new ArgumentException("Secret identity must be defined.", nameof(reference));
        }

        if (canExportMaterial && !canOpenMaterial)
        {
            throw new ArgumentException("Export requires the ability to open material.", nameof(canExportMaterial));
        }

        Reference = reference;
        CanOpenMaterial = canOpenMaterial;
        CanExportMaterial = canExportMaterial;
    }

    /// <summary>Exact, persistent identity of this secret.</summary>
    public SecretReference Reference { get; }

    /// <summary>Provider-declared support for scoped access; not a permission grant.</summary>
    public bool CanOpenMaterial { get; }

    /// <summary>Separate provider-declared export capability; never inferred from open.</summary>
    public bool CanExportMaterial { get; }

    /// <summary>Redacts all provider and secret identity metadata.</summary>
    public override string ToString() => "SecretDescriptor [REDACTED]";
}
