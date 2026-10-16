using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Algorithms;

namespace Laveyana.Security.Agreement;

/// <summary>Strict P-256 ECDH adapter with a separate trusted, exact-version execution boundary.</summary>
/// <remarks>Metadata declarations are preflight only. Key revocation must be enforced again by the executor.</remarks>
public sealed class ManagedKeyAgreementBackend : IManagedKeyAgreementBackend
{
    private readonly IKeyProviderBackend _metadata;
    private readonly IVersionedKeyAgreementOperations _executor;

    /// <summary>Creates an agreement adapter for one stable provider identity.</summary>
    public ManagedKeyAgreementBackend(IKeyProviderBackend metadata, IVersionedKeyAgreementOperations executor)
    {
        _metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        _executor = executor ?? throw new ArgumentNullException(nameof(executor));
        if (!metadata.ProviderId.IsDefined)
        {
            throw new ArgumentException("Provider identity required.", nameof(metadata));
        }
    }

    /// <summary>Gets provider identity.</summary>
    public ProviderId ProviderId => _metadata.ProviderId;

    /// <inheritdoc/>
    public ValueTask<ProviderCapabilitySnapshot> GetCapabilitiesAsync(CancellationToken cancellationToken = default) =>
        _metadata.GetCapabilitiesAsync(cancellationToken);

    /// <inheritdoc/>
    public ValueTask<KeyDescriptor?> FindLogicalAsync(LogicalKeyHandle handle,
        CancellationToken cancellationToken = default) => _metadata.FindLogicalAsync(handle, cancellationToken);

    /// <inheritdoc/>
    public ValueTask<KeyVersionDescriptor?> FindExactAsync(ExactKeyHandle handle,
        CancellationToken cancellationToken = default) => _metadata.FindExactAsync(handle, cancellationToken);

    /// <summary>Checks Active identity, provider and exact version, then dispatches to a revocation-aware executor.</summary>
    public async ValueTask<DerivedKeyLease> AgreeAsync(LogicalKeyHandle privateKey,
        ReadOnlyMemory<byte> peerPublicKeySpki, DerivationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!privateKey.IsDefined || privateKey.ProviderId != ProviderId)
        {
            throw new ArgumentException("The key belongs to another provider.", nameof(privateKey));
        }

        if (peerPublicKeySpki.Length is < 80 or > 512)
        {
            throw new ArgumentException("Expected a bounded P-256 SPKI public key.", nameof(peerPublicKeySpki));
        }

        // Freeze caller-owned SPKI before the first asynchronous suspension.
        byte[] peerSpkiSnapshot = peerPublicKeySpki.ToArray();
        cancellationToken.ThrowIfCancellationRequested();
        ProviderCapabilitySnapshot advertised = await _metadata.GetCapabilitiesAsync(cancellationToken)
            .ConfigureAwait(false);
        if (advertised is null || advertised.ProviderId != ProviderId ||
            !advertised.Supports(WellKnownCapabilities.KeyAgreement))
        {
            throw new CryptographicException("Provider does not permit key agreement.");
        }

        KeyDescriptor logical = await _metadata.FindLogicalAsync(privateKey, cancellationToken)
            .ConfigureAwait(false) ?? throw new CryptographicException("Agreement key is unavailable.");
        if (logical.ProviderId != ProviderId || logical.KeyId != privateKey.KeyId ||
            logical.Kind != KeyKind.AsymmetricPrivate || logical.State != LogicalKeyState.Active ||
            logical.ActiveVersion is not KeyVersion version)
        {
            throw new CryptographicException("Agreement requires an Active asymmetric private key.");
        }

        KeyReference reference = new(ProviderId, privateKey.KeyId, version);
        KeyVersionDescriptor exact = await _metadata.FindExactAsync(new ExactKeyHandle(reference), cancellationToken)
            .ConfigureAwait(false) ?? throw new CryptographicException("Exact agreement version is unavailable.");
        if (exact.Reference != reference || exact.State != KeyVersionState.Active ||
            !exact.Capabilities.Contains(WellKnownCapabilities.KeyAgreement) ||
            exact.Algorithm != WellKnownAlgorithms.EcdhP256)
        {
            throw new CryptographicException("Agreement algorithm, identity, state or capability mismatch.");
        }

        AlgorithmPolicy.EnsureAllowed(exact.Algorithm, AlgorithmPurpose.KeyAgreement, AlgorithmUse.NewOperation);
        cancellationToken.ThrowIfCancellationRequested();
        DerivedKeyLease derived = await _executor.AgreeAsync(reference, exact.Algorithm, peerSpkiSnapshot,
            context, cancellationToken).ConfigureAwait(false);
        if (derived is null)
        {
            throw new CryptographicException("Agreement executor produced no derived key.");
        }
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (derived.Source != reference || derived.Purpose != context.Purpose ||
                derived.Length != context.OutputLength)
            {
                throw new CryptographicException("Agreement executor returned the wrong key identity or length.");
            }

            return derived;
        }
        catch
        {
            derived.Dispose();
            throw;
        }
    }
}
