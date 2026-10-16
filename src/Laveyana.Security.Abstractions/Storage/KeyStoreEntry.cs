using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Protection;

namespace Laveyana.Security.Abstractions.Storage;

/// <summary>One committed immutable logical aggregate snapshot; metadata remains protected.</summary>
public sealed class KeyStoreEntry
{
    /// <summary>Constructs an authoritative revision-bearing entry.</summary>
    public KeyStoreEntry(ProviderId providerId, KeyId keyId, KeyName name,
        KeyStoreRevision revision, ProtectedStoreEnvelope protectedMetadata)
    {
        if (!providerId.IsDefined || !keyId.IsDefined || !name.IsDefined || !revision.IsDefined)
        {
            throw new ArgumentException("All aggregate identities and revision must be defined.");
        }

        ArgumentNullException.ThrowIfNull(protectedMetadata);
        if (protectedMetadata.Purpose != ProtectionPurpose.Metadata)
        {
            throw new ArgumentException("Aggregate metadata must use Metadata protection purpose.", nameof(protectedMetadata));
        }

        ProviderId = providerId;
        KeyId = keyId;
        Name = name;
        Revision = revision;
        ProtectedMetadata = protectedMetadata;
    }

    /// <summary>Gets the durable provider scope.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Gets the durable, never-reassigned logical key identity.</summary>
    public KeyId KeyId { get; }

    /// <summary>Gets the atomically claimed name within the provider.</summary>
    public KeyName Name { get; }

    /// <summary>Gets the revision for conditional changes.</summary>
    public KeyStoreRevision Revision { get; }

    /// <summary>Gets the protected, still unauthenticated aggregate bytes.</summary>
    public ProtectedStoreEnvelope ProtectedMetadata { get; }
}
