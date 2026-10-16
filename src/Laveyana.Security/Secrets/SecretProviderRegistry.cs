using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Secrets;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Diagnostics;

namespace Laveyana.Security.Secrets;

/// <summary>
/// Immutable provider registration snapshot with exact-ID routing. It never
/// enumerates other providers to find a missing secret and does not hold material.
/// </summary>
public sealed class SecretProviderRegistry
{
    private readonly Dictionary<ProviderId, SecretProviderRegistration> _providers = [];
    private readonly Dictionary<ProviderAlias, ProviderId> _aliases = [];
    private readonly SecurityObservability? _observability;

    /// <summary>Validates up to 1024 immutable registrations and unique aliases.</summary>
    public SecretProviderRegistry(IEnumerable<SecretProviderRegistration> registrations,
        SecurityObservability? observability = null)
    {
        ArgumentNullException.ThrowIfNull(registrations);
        _observability = observability;
        foreach (SecretProviderRegistration registration in registrations)
        {
            if (registration is null)
            {
                throw new ArgumentException("Null registration is prohibited.", nameof(registrations));
            }

            if (_providers.Count >= 1024)
            {
                throw new ArgumentException("At most 1024 providers are supported.", nameof(registrations));
            }

            if (!registration.ProviderId.IsDefined || registration.Backend.ProviderId != registration.ProviderId)
            {
                throw new ArgumentException("Provider identity changed during registration.", nameof(registrations));
            }

            if (!_providers.TryAdd(registration.ProviderId, registration))
            {
                throw new ArgumentException("Duplicate provider identity.", nameof(registrations));
            }

            if (registration.Alias is ProviderAlias alias && !_aliases.TryAdd(alias, registration.ProviderId))
            {
                throw new ArgumentException("Duplicate provider alias.", nameof(registrations));
            }
        }
    }

    /// <summary>Number of configured secret providers.</summary>
    public int Count => _providers.Count;

    /// <summary>Looks up only an explicitly registered runtime alias.</summary>
    public bool TryResolveAlias(ProviderAlias alias, out ProviderId providerId)
    {
        if (!alias.IsDefined)
        {
            throw new ArgumentException("A defined alias is required.", nameof(alias));
        }

        return _aliases.TryGetValue(alias, out providerId);
    }

    /// <summary>Requires a registered alias without implicit fallback.</summary>
    public ProviderId ResolveAlias(ProviderAlias alias) => TryResolveAlias(alias, out ProviderId providerId)
        ? providerId
        : throw new KeyNotFoundException("Secret provider alias is not registered.");

    /// <summary>Looks up only the matching stable provider ID.</summary>
    public ISecretProvider GetRequired(ProviderId providerId)
    {
        if (!providerId.IsDefined)
        {
            throw new ArgumentException("A defined provider ID is required.", nameof(providerId));
        }

        if (!_providers.TryGetValue(providerId, out SecretProviderRegistration? registration))
        {
            throw new KeyNotFoundException("Secret provider is not registered.");
        }

        if (registration.Backend.ProviderId != registration.ProviderId)
        {
            throw new InvalidOperationException("Registered secret provider identity changed.");
        }

        return registration.Backend;
    }

    /// <summary>Creates a callback-only handle for the exact persistent identity.</summary>
    public SecretHandle CreateHandle(SecretReference reference)
    {
        if (!reference.IsDefined)
        {
            throw new ArgumentException("A defined secret reference is required.", nameof(reference));
        }

        return new SecretHandle(reference, GetRequired(reference.ProviderId));
    }

    /// <summary>Routes metadata lookups to exactly one provider.</summary>
    public ValueTask<SecretDescriptor?> FindAsync(
        SecretReference reference,
        CancellationToken cancellationToken = default) =>
        CreateHandle(reference).FindAsync(cancellationToken);

    /// <summary>Executes a borrow-only material callback and disposes the result.</summary>
    public ValueTask<bool> UseMaterialAsync(
        SecretReference reference,
        SensitiveMaterialAction visitor,
        CancellationToken cancellationToken = default) =>
        _observability is null ? CreateHandle(reference).UseMaterialAsync(visitor, cancellationToken) :
        _observability.ObserveAsync(SecurityOperation.ReadSecret,
            ct => CreateHandle(reference).UseMaterialAsync(visitor, ct), cancellationToken);

    /// <summary>
    /// Resolves an optional management contract only when explicitly requested.
    /// Read-only providers never need to implement management.
    /// </summary>
    public ISecretManagementProvider RouteManagement(SecretReference reference)
    {
        if (!reference.IsDefined)
        {
            throw new ArgumentException("A defined secret reference is required.", nameof(reference));
        }

        return GetRequired(reference.ProviderId) as ISecretManagementProvider ??
            throw new NotSupportedException("The selected secret provider does not support management.");
    }
}
