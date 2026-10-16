using System.Text;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Storage;

namespace Laveyana.Security.Abstractions.Protection;

/// <summary>Canonical authenticated context for protected software-store records, version 1.</summary>
/// <remarks>
/// Use these bytes as associated data at protect and unprotect boundaries. A protector
/// MUST also cryptographically bind its own identity and purpose; context is public,
/// not an encryption key. Future context changes require explicit format migration.
/// </remarks>
public static class KeyStoreProtectionContext
{
    /// <summary>Binds metadata to its exact aggregate identity and committed revision.</summary>
    public static byte[] ForMetadata(ProviderId providerId, KeyId keyId, KeyStoreRevision revision)
    {
        if (!providerId.IsDefined || !keyId.IsDefined || !revision.IsDefined)
        {
            throw new ArgumentException("Metadata protection context needs defined identity and revision.");
        }

        return Encoding.ASCII.GetBytes($"Laveyana.Security/store/v1/metadata/{providerId}/{keyId}/{revision}");
    }

    /// <summary>Binds encrypted material to an exact provider, key and version.</summary>
    public static byte[] ForKeyMaterial(KeyReference reference)
    {
        if (!reference.IsDefined)
        {
            throw new ArgumentException("Material protection context needs an exact key reference.", nameof(reference));
        }

        return Encoding.ASCII.GetBytes($"Laveyana.Security/store/v1/material/{reference}");
    }
}
