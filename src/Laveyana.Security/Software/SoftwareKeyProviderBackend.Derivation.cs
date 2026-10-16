using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Algorithms;

namespace Laveyana.Security.Software;

/// <summary>Provider-owned HKDF-SHA-256 over an Active, protected, symmetric derivation key.</summary>
public sealed partial class SoftwareKeyProviderBackend
{
    /// <summary>Never exports the source key; returns an ephemeral, disposable derived-key capability.</summary>
    public async ValueTask<DerivedKeyLease> DeriveAsync(LogicalKeyHandle source,
        DerivationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        Validate(source);
        cancellationToken.ThrowIfCancellationRequested();
        KeyStoreEntry entry = await RequireCorrectEntryAsync(source, cancellationToken).ConfigureAwait(false);
        SoftwareKeyMetadata metadata = await ReadAsync(entry, cancellationToken).ConfigureAwait(false);
        if (metadata.Kind != KeyKind.Symmetric || metadata.Algorithm != WellKnownAlgorithms.HkdfSha256 ||
            metadata.Lifecycle.State != LogicalKeyState.Active ||
            metadata.Lifecycle.ActiveVersion is not KeyVersion version ||
            !metadata.Capabilities.Contains(WellKnownCapabilities.Derive) ||
            metadata.Lifecycle.Find(version)?.State != KeyVersionState.Active)
        {
            throw new CryptographicException("Derivation requires an Active HKDF key and capability.");
        }

        AlgorithmPolicy.EnsureAllowed(metadata.Algorithm, AlgorithmPurpose.GeneralKdf, AlgorithmUse.NewOperation);
        KeyReference reference = new(ProviderId, source.KeyId, version);
        using SensitiveMaterialLease secret = await ReadKeyMaterialAsync(reference, entry.Revision,
            cancellationToken).ConfigureAwait(false);
        byte[] info = context.BuildSymmetricInfo(reference);
        byte[] salt = SHA256.HashData(info);
        byte[]? derived = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            derived = new byte[context.OutputLength];
            secret.UseMaterial(material =>
            {
                if (material.Length < 32)
                {
                    throw new CryptographicException("HKDF source must have at least 32 bytes.");
                }
                HKDF.DeriveKey(HashAlgorithmName.SHA256, material, derived, salt, info);
            });
            cancellationToken.ThrowIfCancellationRequested();
            DerivedKeyLease result = new(reference, context.Purpose, derived);
            derived = null;
            return result;
        }
        finally
        {
            if (derived is not null)
            {
                CryptographicOperations.ZeroMemory(derived);
            }
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(info);
        }
    }
}
