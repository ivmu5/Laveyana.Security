using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Nonce;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Abstractions.Secrets;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Software;
using Laveyana.Security.Diagnostics;
using Microsoft.Extensions.DependencyInjection;

namespace Laveyana.Security.DependencyInjection.Composition;

/// <summary>
/// Explicit, one-shot security composition. No platform discovery, plaintext protection,
/// implicit store creation or background rotation is performed.
/// </summary>
public sealed class SecurityCompositionBuilder
{
    private readonly IServiceCollection _services;
    private readonly List<KeyProviderFactory> _keyProviders = [];
    private readonly List<SecretProviderFactory> _secretProviders = [];
    private readonly List<RequiredCapability> _requiredCapabilities = [];
    private Func<IServiceProvider, IKeyStore>? _store;
    private Func<IServiceProvider, IKeyStoreProtector>? _protector;
    private Func<IServiceProvider, IRollbackProtectedNonceAllocator>? _nonceAllocator;
    private TimeProvider _timeProvider = TimeProvider.System;
    private SecurityObservability? _observability;
    private bool _sealed;

    internal SecurityCompositionBuilder(IServiceCollection services) => _services = services;

    /// <summary>Registers a preconstructed, stable-identity key backend as a singleton composition member.</summary>
    public SecurityCompositionBuilder UseKeyProvider(IKeyProviderBackend backend, ProviderAlias? alias = null)
    {
        ArgumentNullException.ThrowIfNull(backend);
        EnsureMutable();
        ValidateIdentity(backend.ProviderId, alias);
        _keyProviders.Add(new(backend.ProviderId, alias, _ => backend));
        return this;
    }

    /// <summary>
    /// Uses an already registered singleton backend. Scoped/transient registrations and
    /// multiple registrations of the same concrete service type are rejected.
    /// </summary>
    public SecurityCompositionBuilder UseKeyProvider<TBackend>(ProviderId providerId, ProviderAlias? alias = null)
        where TBackend : class, IKeyProviderBackend
    {
        EnsureMutable();
        ValidateIdentity(providerId, alias);
        RequireSingleton<TBackend>();
        _keyProviders.Add(new(providerId, alias, sp => sp.GetRequiredService<TBackend>()));
        return this;
    }

    /// <summary>Registers one read-oriented secret provider, independent of key lifecycle.</summary>
    public SecurityCompositionBuilder UseSecretProvider(ISecretProvider backend, ProviderAlias? alias = null)
    {
        ArgumentNullException.ThrowIfNull(backend);
        EnsureMutable();
        ValidateIdentity(backend.ProviderId, alias);
        _secretProviders.Add(new(backend.ProviderId, alias, _ => backend));
        return this;
    }

    /// <summary>Uses an existing singleton secret provider managed by the application.</summary>
    public SecurityCompositionBuilder UseSecretProvider<TBackend>(ProviderId providerId, ProviderAlias? alias = null)
        where TBackend : class, ISecretProvider
    {
        EnsureMutable();
        ValidateIdentity(providerId, alias);
        RequireSingleton<TBackend>();
        _secretProviders.Add(new(providerId, alias, sp => sp.GetRequiredService<TBackend>()));
        return this;
    }

    /// <summary>Selects one explicitly configured authenticated at-rest protector.</summary>
    public SecurityCompositionBuilder UseProtector(IKeyStoreProtector protector)
    {
        ArgumentNullException.ThrowIfNull(protector);
        EnsureMutable();
        if (!protector.CurrentReference.IsDefined)
        {
            throw new ArgumentException("Protector reference must be defined.", nameof(protector));
        }

        SelectProtector(_ => protector);
        return this;
    }

    /// <summary>Selects an already registered singleton protector, never a platform guess.</summary>
    public SecurityCompositionBuilder UseProtector<TProtector>() where TProtector : class, IKeyStoreProtector
    {
        EnsureMutable();
        RequireSingleton<TProtector>();
        SelectProtector(sp => sp.GetRequiredService<TProtector>());
        return this;
    }

    /// <summary>Selects an already opened, application-owned durable store.</summary>
    public SecurityCompositionBuilder UseStore(IKeyStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        EnsureMutable();
        SelectStore(_ => store);
        return this;
    }

    /// <summary>Selects a singleton store that has been explicitly initialized by the application.</summary>
    public SecurityCompositionBuilder UseStore<TStore>() where TStore : class, IKeyStore
    {
        EnsureMutable();
        RequireSingleton<TStore>();
        SelectStore(sp => sp.GetRequiredService<TStore>());
        return this;
    }

    /// <summary>Supplies an independently secured nonce allocator; never silently creates one.</summary>
    public SecurityCompositionBuilder UseNonceAllocator(IRollbackProtectedNonceAllocator allocator)
    {
        ArgumentNullException.ThrowIfNull(allocator);
        EnsureMutable();
        if (_nonceAllocator is not null)
        {
            throw new InvalidOperationException("Only one nonce allocator may be selected.");
        }

        _nonceAllocator = _ => allocator;
        return this;
    }

    /// <summary>
    /// Registers a store-backed software provider using the selected store and protector.
    /// These dependencies must exist; no plaintext or in-memory fallback is available.
    /// </summary>
    public SecurityCompositionBuilder UseSoftwareProvider(ProviderId providerId, ProviderAlias? alias = null)
    {
        EnsureMutable();
        ValidateIdentity(providerId, alias);
        _keyProviders.Add(new(providerId, alias, sp => new SoftwareKeyProviderBackend(providerId,
            sp.GetRequiredService<IKeyStore>(), sp.GetRequiredService<IKeyStoreProtector>(),
            _nonceAllocator is null ? null : sp.GetRequiredService<IRollbackProtectedNonceAllocator>(),
            _observability), true));
        return this;
    }

    /// <summary>
    /// Requires advertised provider-wide capability at host startup; this is never treated
    /// as operation authorization and must still be checked at execution time.
    /// </summary>
    public SecurityCompositionBuilder RequireCapability(ProviderId providerId, CapabilityId capability)
    {
        EnsureMutable();
        if (!providerId.IsDefined || !capability.IsDefined)
        {
            throw new ArgumentException("A defined provider and capability are required.");
        }

        _requiredCapabilities.Add(new(providerId, capability));
        return this;
    }

    /// <summary>Opts into bounded managed diagnostics, metrics, tracing and optional audit delivery.</summary>
    public SecurityCompositionBuilder WithObservability(SecurityObservability observability)
    {
        EnsureMutable();
        ArgumentNullException.ThrowIfNull(observability);
        if (_observability is not null)
        {
            throw new InvalidOperationException("Only one observability boundary may be configured.");
        }

        _observability = observability;
        return this;
    }

    /// <summary>Sets a clock for explicitly scheduled policies; no worker is started.</summary>
    public SecurityCompositionBuilder WithTimeProvider(TimeProvider timeProvider)
    {
        EnsureMutable();
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        return this;
    }

    internal SecurityCompositionPlan Seal(bool requireDefaults)
    {
        EnsureMutable();
        _sealed = true;
        if (requireDefaults && _protector is null)
        {
            throw new InvalidOperationException("Safe defaults require an explicitly selected protector.");
        }

        if (_store is not null && _protector is null)
        {
            throw new InvalidOperationException("A persistent store requires an authenticated protector.");
        }

        if (_keyProviders.Any(item => item.IsSoftware) && (_store is null || _protector is null))
        {
            throw new InvalidOperationException("A software backend requires a store and protector.");
        }

        HashSet<ProviderId> keyIds = [];
        HashSet<ProviderId> secretIds = [];
        HashSet<ProviderAlias> aliases = [];
        foreach (KeyProviderFactory entry in _keyProviders)
        {
            if (!keyIds.Add(entry.Id) || (entry.Alias is ProviderAlias alias && !aliases.Add(alias)))
            {
                throw new InvalidOperationException("Duplicate key provider identity or alias.");
            }
        }

        foreach (SecretProviderFactory entry in _secretProviders)
        {
            if (!secretIds.Add(entry.Id) || (entry.Alias is ProviderAlias alias && !aliases.Add(alias)))
            {
                throw new InvalidOperationException("Duplicate secret identity or ambiguous alias.");
            }
        }

        if (_requiredCapabilities.Any(item => !keyIds.Contains(item.ProviderId)))
        {
            throw new InvalidOperationException("Capability requirement refers to an unregistered key provider.");
        }

        return new SecurityCompositionPlan(_keyProviders.ToArray(), _secretProviders.ToArray(),
            _requiredCapabilities.Distinct().ToArray(), _store, _protector, _nonceAllocator, _timeProvider, _observability);
    }

    private void SelectStore(Func<IServiceProvider, IKeyStore> factory)
    {
        if (_store is not null)
        {
            throw new InvalidOperationException("Only one store may be selected.");
        }

        _store = factory;
    }

    private void SelectProtector(Func<IServiceProvider, IKeyStoreProtector> factory)
    {
        if (_protector is not null)
        {
            throw new InvalidOperationException("Only one current protector may be selected.");
        }

        _protector = factory;
    }

    private void RequireSingleton<T>() where T : class
    {
        ServiceDescriptor[] matches = _services.Where(item => item.ServiceType == typeof(T)).ToArray();
        if (matches.Length != 1 || matches[0].Lifetime != ServiceLifetime.Singleton)
        {
            throw new InvalidOperationException("Referenced services must have exactly one pre-existing singleton registration.");
        }
    }

    private void EnsureMutable()
    {
        if (_sealed)
        {
            throw new InvalidOperationException("Security configuration has already been frozen.");
        }
    }

    private static void ValidateIdentity(ProviderId id, ProviderAlias? alias)
    {
        if (!id.IsDefined || (alias.HasValue && !alias.Value.IsDefined))
        {
            throw new ArgumentException("Provider and optional alias must be defined.");
        }
    }

    internal sealed record KeyProviderFactory(ProviderId Id, ProviderAlias? Alias,
        Func<IServiceProvider, IKeyProviderBackend> Create, bool IsSoftware = false);
    internal sealed record SecretProviderFactory(ProviderId Id, ProviderAlias? Alias,
        Func<IServiceProvider, ISecretProvider> Create);
    internal readonly record struct RequiredCapability(ProviderId ProviderId, CapabilityId Capability);

    internal sealed record SecurityCompositionPlan(
        KeyProviderFactory[] Keys, SecretProviderFactory[] Secrets, RequiredCapability[] Requirements,
        Func<IServiceProvider, IKeyStore>? Store,
        Func<IServiceProvider, IKeyStoreProtector>? Protector,
        Func<IServiceProvider, IRollbackProtectedNonceAllocator>? NonceAllocator,
        TimeProvider TimeProvider, SecurityObservability? Observability);
}
