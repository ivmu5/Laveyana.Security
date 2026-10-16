using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Protection;

namespace Laveyana.Security.Abstractions.Storage;

/// <summary>A conditional, all-or-nothing metadata and material update for one key generation.</summary>
public sealed class KeyStoreReplaceRequest
{
    /// <summary>Creates a mutation whose expected revision is checked at the durable commit point.</summary>
    public KeyStoreReplaceRequest(ProviderId providerId, KeyId keyId, KeyStoreRevision expectedRevision,
        ProtectedStoreEnvelope protectedMetadata, IEnumerable<KeyStoreMaterialChange> materialChanges)
    {
        if (!providerId.IsDefined || !keyId.IsDefined || !expectedRevision.IsDefined)
        {
            throw new ArgumentException("Replace identity and expected revision must be defined.");
        }

        ArgumentNullException.ThrowIfNull(protectedMetadata);
        if (protectedMetadata.Purpose != ProtectionPurpose.Metadata)
        {
            throw new ArgumentException("Metadata purpose is required.", nameof(protectedMetadata));
        }

        ProviderId = providerId;
        KeyId = keyId;
        ExpectedRevision = expectedRevision;
        ProtectedMetadata = protectedMetadata;
        MaterialChanges = KeyStoreRequestValidation.CopyChanges(providerId, keyId, materialChanges, true);
    }

    /// <summary>Gets the provider scope.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Gets the aggregate identity; existing name binding must remain unchanged.</summary>
    public KeyId KeyId { get; }

    /// <summary>Gets the revision required for successful CAS.</summary>
    public KeyStoreRevision ExpectedRevision { get; }

    /// <summary>Gets the replacement protected aggregate state.</summary>
    public ProtectedStoreEnvelope ProtectedMetadata { get; }

    /// <summary>Gets version-scoped upserts/removals to commit atomically with metadata.</summary>
    public IReadOnlyList<KeyStoreMaterialChange> MaterialChanges { get; }
}
