using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Protection;

namespace Laveyana.Security.Abstractions.Storage;

/// <summary>Atomically creates a logical aggregate, unique name binding and initial protected material.</summary>
public sealed class KeyStoreCreateRequest
{
    /// <summary>Creates an immutable request; callers must protect/bind metadata and material before use.</summary>
    public KeyStoreCreateRequest(ProviderId providerId, KeyId keyId, KeyName name,
        ProtectedStoreEnvelope protectedMetadata, IEnumerable<KeyStoreMaterialChange> initialMaterial)
    {
        if (!providerId.IsDefined || !keyId.IsDefined || !name.IsDefined)
        {
            throw new ArgumentException("All creation identities must be defined.");
        }

        ArgumentNullException.ThrowIfNull(protectedMetadata);
        if (protectedMetadata.Purpose != ProtectionPurpose.Metadata)
        {
            throw new ArgumentException("Metadata purpose is required.", nameof(protectedMetadata));
        }

        ProviderId = providerId;
        KeyId = keyId;
        Name = name;
        ProtectedMetadata = protectedMetadata;
        InitialMaterial = KeyStoreRequestValidation.CopyChanges(providerId, keyId, initialMaterial, false);
        if (InitialMaterial.Count != 1 || InitialMaterial[0].Reference.Version != new KeyVersion(1))
        {
            throw new ArgumentException("Initial Active generation requires exactly version 1 protected material.", nameof(initialMaterial));
        }
    }

    /// <summary>Gets the provider scope.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Gets the new key generation ID.</summary>
    public KeyId KeyId { get; }

    /// <summary>Gets the unique logical name in the provider scope.</summary>
    public KeyName Name { get; }

    /// <summary>Gets protected aggregate state.</summary>
    public ProtectedStoreEnvelope ProtectedMetadata { get; }

    /// <summary>Gets protected initial material writes; no removal is permitted on create.</summary>
    public IReadOnlyList<KeyStoreMaterialChange> InitialMaterial { get; }
}
