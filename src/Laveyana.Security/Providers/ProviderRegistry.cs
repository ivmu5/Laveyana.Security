using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Diagnostics;

namespace Laveyana.Security.Providers;

/// <summary>
/// Immutable composition-time registry. All key reads route by the exact ProviderId;
/// runtime aliases are resolved only when explicitly requested.
/// </summary>
/// <remarks>
/// Registry membership and aliases cannot change after construction. Backend state,
/// metadata and capability advertisements can change and must be checked at use time.
/// This registry does not authorize or execute cryptographic operations.
/// </remarks>
public sealed class ProviderRegistry : IKeyMetadataResolver
{
    private readonly Dictionary<ProviderId, ProviderRegistration> _registrations;
    private readonly Dictionary<ProviderAlias, ProviderId> _aliases;
    private readonly SecurityObservability? _observability;

    /// <summary>
    /// Validates and captures an immutable configuration snapshot of up to 1024 providers.
    /// Duplicate identities and aliases fail startup rather than selecting a winner.
    /// </summary>
    public ProviderRegistry(IEnumerable<ProviderRegistration> registrations,
        SecurityObservability? observability = null)
    {
        ArgumentNullException.ThrowIfNull(registrations);
        _observability = observability;
        _registrations = [];
        _aliases = [];

        foreach (ProviderRegistration registration in registrations)
        {
            if (registration is null)
            {
                throw new ArgumentException("Null provider registration is not allowed.", nameof(registrations));
            }

            if (_registrations.Count >= 1024)
            {
                throw new ArgumentException("At most 1024 providers may be registered.", nameof(registrations));
            }

            if (!registration.ProviderId.IsDefined || registration.Backend.ProviderId != registration.ProviderId)
            {
                throw new ArgumentException("Provider identity changed during registration.", nameof(registrations));
            }

            if (!_registrations.TryAdd(registration.ProviderId, registration))
            {
                throw new ArgumentException("Duplicate provider identity.", nameof(registrations));
            }

            if (registration.Alias is ProviderAlias alias && !_aliases.TryAdd(alias, registration.ProviderId))
            {
                throw new ArgumentException("Duplicate provider alias.", nameof(registrations));
            }
        }
    }

    /// <summary>Gets the number of registered providers in this fixed snapshot.</summary>
    public int Count => _registrations.Count;

    /// <summary>Resolves only an explicitly configured, case-sensitive runtime alias.</summary>
    public bool TryResolveAlias(ProviderAlias alias, out ProviderId providerId)
    {
        if (!alias.IsDefined)
        {
            throw new ArgumentException("A defined alias is required.", nameof(alias));
        }

        return _aliases.TryGetValue(alias, out providerId);
    }

    /// <summary>Resolves a runtime alias or fails closed; aliases must not be persisted as key identity.</summary>
    public ProviderId ResolveAlias(ProviderAlias alias) => TryResolveAlias(alias, out ProviderId id)
        ? id
        : throw new KeyNotFoundException("Provider alias is not registered.");

    /// <summary>Routes AEAD to the exact owning provider or rejects unsupported implementations.</summary>
    public IAuthenticatedEncryptionBackend RouteAead(LogicalKeyHandle handle) =>
        Route(handle) as IAuthenticatedEncryptionBackend ??
        throw new NotSupportedException("The selected provider does not implement authenticated encryption.");

    /// <summary>Routes historical AEAD using the immutable provider ID in the payload reference.</summary>
    public IAuthenticatedEncryptionBackend RouteAead(KeyReference reference) =>
        Route(reference) as IAuthenticatedEncryptionBackend ??
        throw new NotSupportedException("The selected provider does not implement authenticated encryption.");

    /// <summary>Routes HMAC computation to the owning provider without scanning others.</summary>
    public IManagedMacBackend RouteMac(LogicalKeyHandle handle) =>
        Route(handle) as IManagedMacBackend ??
        throw new NotSupportedException("The selected provider does not implement MAC operations.");

    /// <summary>Routes historical MAC verification by the exact immutable key reference.</summary>
    public IManagedMacBackend RouteMac(KeyReference reference) =>
        Route(reference) as IManagedMacBackend ??
        throw new NotSupportedException("The selected provider does not implement MAC operations.");

    /// <summary>Routes streaming MAC creation to the owning provider without fallback.</summary>
    public IStreamingMacBackend RouteStreamingMac(LogicalKeyHandle handle) =>
        Route(handle) as IStreamingMacBackend ??
        throw new NotSupportedException("The selected provider does not implement streaming MAC.");

    /// <summary>Routes streaming MAC verification by the exact historical provider identity.</summary>
    public IStreamingMacBackend RouteStreamingMac(KeyReference reference) =>
        Route(reference) as IStreamingMacBackend ??
        throw new NotSupportedException("The selected provider does not implement streaming MAC.");

    /// <summary>Routes signing using the exact owning provider.</summary>
    public IManagedSignatureBackend RouteSignature(LogicalKeyHandle handle) =>
        Route(handle) as IManagedSignatureBackend ??
        throw new NotSupportedException("The selected provider does not implement signing.");

    /// <summary>Routes historical verification by the signature's embedded reference.</summary>
    public IManagedSignatureBackend RouteSignature(KeyReference reference) =>
        Route(reference) as IManagedSignatureBackend ??
        throw new NotSupportedException("The selected provider does not implement signing.");

    /// <summary>Routes P-256 agreement only by the stable owner identity.</summary>
    public IManagedKeyAgreementBackend RouteAgreement(LogicalKeyHandle handle) =>
        Route(handle) as IManagedKeyAgreementBackend ??
        throw new NotSupportedException("The selected provider does not implement key agreement.");

    /// <summary>Routes symmetric HKDF to an authoritative key owner.</summary>
    public IManagedDerivationBackend RouteDerivation(LogicalKeyHandle handle) =>
        Route(handle) as IManagedDerivationBackend ??
        throw new NotSupportedException("The selected provider does not implement derivation.");

    /// <summary>Gets exactly one backend by stable persistent ID, never scanning providers.</summary>
    public IKeyProviderBackend GetRequired(ProviderId providerId)
    {
        if (!providerId.IsDefined)
        {
            throw new ArgumentException("A defined provider identity is required.", nameof(providerId));
        }

        if (!_registrations.TryGetValue(providerId, out ProviderRegistration? registration))
        {
            throw new KeyNotFoundException("Provider identity is not registered.");
        }

        if (registration.Backend.ProviderId != registration.ProviderId)
        {
            throw new InvalidOperationException("Registered backend identity changed.");
        }

        return registration.Backend;
    }

    /// <summary>Routes a logical key to its exact owning provider.</summary>
    public IKeyProviderBackend Route(LogicalKeyHandle handle)
    {
        if (!handle.IsDefined)
        {
            throw new ArgumentException("A defined logical handle is required.", nameof(handle));
        }

        return GetRequired(handle.ProviderId);
    }

    /// <summary>Routes an exact material version without resolving a runtime alias.</summary>
    public IKeyProviderBackend Route(ExactKeyHandle handle)
    {
        if (!handle.IsDefined)
        {
            throw new ArgumentException("A defined exact handle is required.", nameof(handle));
        }

        return GetRequired(handle.Reference.ProviderId);
    }

    /// <summary>Routes a persisted reference directly by its immutable provider identity.</summary>
    public IKeyProviderBackend Route(KeyReference reference)
    {
        if (!reference.IsDefined)
        {
            throw new ArgumentException("A defined key reference is required.", nameof(reference));
        }

        return GetRequired(reference.ProviderId);
    }

    /// <summary>
    /// Retrieves provider-wide declared capabilities and rejects a cross-provider or
    /// stale-identity response. A declaration is not authorization to perform work.
    /// </summary>
    public async ValueTask<ProviderCapabilitySnapshot> GetCapabilitiesAsync(
        ProviderId providerId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IKeyProviderBackend backend = GetRequired(providerId);
        ProviderCapabilitySnapshot snapshot = await backend.GetCapabilitiesAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureIdentity(backend, providerId);
        if (snapshot is null || snapshot.ProviderId != providerId)
        {
            throw new InvalidOperationException("Backend returned a different provider identity.");
        }

        return snapshot;
    }

    /// <summary>Routes a logical metadata read directly to its owning provider.</summary>
    public ValueTask<KeyDescriptor?> FindLogicalAsync(
        LogicalKeyHandle handle,
        CancellationToken cancellationToken = default) =>
        _observability is null ? FindLogicalCoreAsync(handle, cancellationToken) :
        _observability.ObserveAsync(SecurityOperation.ReadKey,
            ct => FindLogicalCoreAsync(handle, ct), cancellationToken);

    private async ValueTask<KeyDescriptor?> FindLogicalCoreAsync(LogicalKeyHandle handle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IKeyProviderBackend backend = Route(handle);
        KeyDescriptor? descriptor = await backend.FindLogicalAsync(handle, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureIdentity(backend, handle.ProviderId);
        if (descriptor is not null && (descriptor.ProviderId != handle.ProviderId || descriptor.KeyId != handle.KeyId))
        {
            throw new InvalidOperationException("Backend returned metadata for another logical key.");
        }

        return descriptor;
    }

    /// <summary>Routes an exact-version metadata read directly to its owning provider.</summary>
    public ValueTask<KeyVersionDescriptor?> FindExactAsync(
        ExactKeyHandle handle,
        CancellationToken cancellationToken = default) =>
        _observability is null ? FindExactCoreAsync(handle, cancellationToken) :
        _observability.ObserveAsync(SecurityOperation.ReadKey,
            ct => FindExactCoreAsync(handle, ct), cancellationToken);

    private async ValueTask<KeyVersionDescriptor?> FindExactCoreAsync(ExactKeyHandle handle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IKeyProviderBackend backend = Route(handle);
        KeyVersionDescriptor? descriptor = await backend.FindExactAsync(handle, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureIdentity(backend, handle.Reference.ProviderId);
        if (descriptor is not null && descriptor.Reference != handle.Reference)
        {
            throw new InvalidOperationException("Backend returned metadata for another key version.");
        }

        return descriptor;
    }

    private static void EnsureIdentity(IKeyProviderBackend backend, ProviderId providerId)
    {
        if (backend.ProviderId != providerId)
        {
            throw new InvalidOperationException("Registered backend identity changed.");
        }
    }
}
