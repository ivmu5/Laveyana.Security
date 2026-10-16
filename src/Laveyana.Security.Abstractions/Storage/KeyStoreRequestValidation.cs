using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Storage;

internal static class KeyStoreRequestValidation
{
    internal const int MaximumChanges = 128;
    internal const long MaximumTotalEncodedLength = 16L * 1024 * 1024;

    internal static IReadOnlyList<KeyStoreMaterialChange> CopyChanges(
        ProviderId providerId, KeyId keyId, IEnumerable<KeyStoreMaterialChange> changes, bool allowDeletes)
    {
        ArgumentNullException.ThrowIfNull(changes);
        List<KeyStoreMaterialChange> copy = new();
        HashSet<KeyVersion> versions = new();
        long encodedLength = 0;
        foreach (KeyStoreMaterialChange change in changes)
        {
            if (change is null || change.Reference.ProviderId != providerId ||
                change.Reference.KeyId != keyId || (change.IsDelete && !allowDeletes) ||
                !versions.Add(change.Reference.Version))
            {
                throw new ArgumentException("Invalid, cross-key, duplicate or disallowed material change.", nameof(changes));
            }

            encodedLength += change.Material?.EncodedLength ?? 0;
            copy.Add(change);
            if (encodedLength > MaximumTotalEncodedLength || copy.Count > MaximumChanges)
            {
                throw new ArgumentOutOfRangeException(nameof(changes), "Material changes exceed the allowed transaction budget.");
            }
        }

        return copy.AsReadOnly();
    }
}
