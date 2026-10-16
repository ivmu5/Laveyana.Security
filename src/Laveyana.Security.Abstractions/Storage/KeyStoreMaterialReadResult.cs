using Laveyana.Security.Abstractions.Protection;

namespace Laveyana.Security.Abstractions.Storage;

/// <summary>One definite version-scoped read outcome.</summary>
public readonly record struct KeyStoreMaterialReadResult
{
    private KeyStoreMaterialReadResult(KeyStoreMaterialReadStatus status, ProtectedStoreEnvelope? material)
    {
        Status = status;
        ProtectedMaterial = material;
    }

    /// <summary>Gets the defined read outcome.</summary>
    public KeyStoreMaterialReadStatus Status { get; }

    /// <summary>Gets the still-encrypted envelope on Found only.</summary>
    public ProtectedStoreEnvelope? ProtectedMaterial { get; }

    /// <summary>Creates a successful read.</summary>
    public static KeyStoreMaterialReadResult Found(ProtectedStoreEnvelope material)
    {
        ArgumentNullException.ThrowIfNull(material);
        if (material.Purpose != ProtectionPurpose.KeyMaterial)
        {
            throw new ArgumentException("Expected KeyMaterial purpose.", nameof(material));
        }

        return new KeyStoreMaterialReadResult(KeyStoreMaterialReadStatus.Found, material);
    }

    /// <summary>Creates a definite absence or stale-revision result.</summary>
    public static KeyStoreMaterialReadResult Rejected(KeyStoreMaterialReadStatus status) => status is
        KeyStoreMaterialReadStatus.NotFound or KeyStoreMaterialReadStatus.RevisionMismatch
            ? new(status, null)
            : throw new ArgumentOutOfRangeException(nameof(status));
}
