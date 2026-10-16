using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Protection;

namespace Laveyana.Security.Abstractions.Storage;

/// <summary>A version-scoped protected material upsert or deletion applied in the aggregate transaction.</summary>
public sealed class KeyStoreMaterialChange
{
    private KeyStoreMaterialChange(KeyReference reference, ProtectedStoreEnvelope? material)
    {
        if (!reference.IsDefined)
        {
            throw new ArgumentException("A material reference must be defined.", nameof(reference));
        }

        if (material is not null && material.Purpose != ProtectionPurpose.KeyMaterial)
        {
            throw new ArgumentException("Material must use KeyMaterial protection purpose.", nameof(material));
        }

        Reference = reference;
        Material = material;
    }

    /// <summary>Gets the exact key material reference.</summary>
    public KeyReference Reference { get; }

    /// <summary>Gets protected material for an upsert, or null for a durable removal.</summary>
    public ProtectedStoreEnvelope? Material { get; }

    /// <summary>Gets whether the change removes material.</summary>
    public bool IsDelete => Material is null;

    /// <summary>Creates a protected-material upsert.</summary>
    public static KeyStoreMaterialChange Upsert(KeyReference reference, ProtectedStoreEnvelope material)
    {
        ArgumentNullException.ThrowIfNull(material);
        return new KeyStoreMaterialChange(reference, material);
    }

    /// <summary>Creates a protected-material deletion.</summary>
    public static KeyStoreMaterialChange Delete(KeyReference reference) => new(reference, null);
}
