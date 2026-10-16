using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Nonce;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Abstractions.Secrets;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Providers;
using Laveyana.Security.Secrets;
using Microsoft.Extensions.DependencyInjection;

namespace Laveyana.Security.DependencyInjection.Composition;

/// <summary>
/// Fixed, validated process-level composition. Provider availability and permissions
/// are dynamic and must still be verified by the backend at each operation.
/// </summary>
public sealed class SecurityCompositionSnapshot
{
    private readonly SecurityCompositionBuilder.RequiredCapability[] _requirements;

    private SecurityCompositionSnapshot(ProviderRegistry keys, SecretProviderRegistry secrets,
        IKeyStore? store, IKeyStoreProtector? protector, IRollbackProtectedNonceAllocator? allocator,
        TimeProvider timeProvider, SecurityCompositionBuilder.RequiredCapability[] requirements)
    {
        KeyProviders = keys;
        SecretProviders = secrets;
        Store = store;
        Protector = protector;
        NonceAllocator = allocator;
        TimeProvider = timeProvider;
        _requirements = requirements;
    }

    /// <summary>Stable key provider identities and case-sensitive aliases.</summary>
    public ProviderRegistry KeyProviders { get; }

    /// <summary>Stable secret provider identities and read-only handles.</summary>
    public SecretProviderRegistry SecretProviders { get; }

    /// <summary>Configured store, if any. No implicit store is created.</summary>
    public IKeyStore? Store { get; }

    /// <summary>The only current-write authenticated protector, if selected.</summary>
    public IKeyStoreProtector? Protector { get; }

    /// <summary>Explicit rollback-resistant allocator, if configured.</summary>
    public IRollbackProtectedNonceAllocator? NonceAllocator { get; }

    /// <summary>Clock for future explicit time-dependent policies.</summary>
    public TimeProvider TimeProvider { get; }

    /// <summary>
    /// Checks live provider-wide capabilities at host startup or on explicit request.
    /// These snapshots do not grant authorization for any subsequent operation.
    /// </summary>
    public async ValueTask ValidateCapabilitiesAsync(CancellationToken cancellationToken = default)
    {
        foreach (SecurityCompositionBuilder.RequiredCapability required in _requirements)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IKeyProviderBackend backend = KeyProviders.GetRequired(required.ProviderId);
            ProviderCapabilitySnapshot advertised = await backend.GetCapabilitiesAsync(cancellationToken)
                .ConfigureAwait(false);
            if (advertised is null || advertised.ProviderId != required.ProviderId ||
                backend.ProviderId != required.ProviderId || !advertised.Supports(required.Capability) ||
                !SupportsOperationInterface(backend, required.Capability))
            {
                throw new InvalidOperationException("Provider capability requirement was not met at startup.");
            }
        }
    }

    private static bool SupportsOperationInterface(IKeyProviderBackend backend, CapabilityId capability)
    {
        if (capability == WellKnownCapabilities.Encrypt || capability == WellKnownCapabilities.Decrypt)
        {
            return backend is IAuthenticatedEncryptionBackend;
        }

        if (capability == WellKnownCapabilities.Mac || capability == WellKnownCapabilities.VerifyMac)
        {
            return backend is IManagedMacBackend;
        }

        if (capability == WellKnownCapabilities.Sign || capability == WellKnownCapabilities.VerifySignature)
        {
            return backend is IManagedSignatureBackend;
        }

        if (capability == WellKnownCapabilities.KeyAgreement)
        {
            return backend is IManagedKeyAgreementBackend;
        }

        if (capability == WellKnownCapabilities.Derive)
        {
            return backend is IManagedDerivationBackend;
        }

        return true;
    }

    internal static SecurityCompositionSnapshot Create(IServiceProvider provider,
        SecurityCompositionBuilder.SecurityCompositionPlan plan)
    {
        IKeyStore? store = plan.Store is null ? null : provider.GetRequiredService<IKeyStore>();
        IKeyStoreProtector? protector = plan.Protector is null ? null : provider.GetRequiredService<IKeyStoreProtector>();
        IRollbackProtectedNonceAllocator? allocator = plan.NonceAllocator is null
            ? null : provider.GetRequiredService<IRollbackProtectedNonceAllocator>();
        if ((store is not null && protector is null) ||
            (protector is not null && !protector.CurrentReference.IsDefined))
        {
            throw new InvalidOperationException("Invalid store/protector composition.");
        }

        List<ProviderRegistration> keys = [];
        foreach (SecurityCompositionBuilder.KeyProviderFactory factory in plan.Keys)
        {
            IKeyProviderBackend backend = factory.Create(provider) ??
                throw new InvalidOperationException("A key backend factory returned null.");
            if (backend.ProviderId != factory.Id)
            {
                throw new InvalidOperationException("Configured key provider identity differs from its backend.");
            }

            keys.Add(new ProviderRegistration(backend, factory.Alias));
        }

        List<SecretProviderRegistration> secrets = [];
        foreach (SecurityCompositionBuilder.SecretProviderFactory factory in plan.Secrets)
        {
            ISecretProvider backend = factory.Create(provider) ??
                throw new InvalidOperationException("A secret provider factory returned null.");
            if (backend.ProviderId != factory.Id)
            {
                throw new InvalidOperationException("Configured secret provider identity differs from its backend.");
            }

            secrets.Add(new SecretProviderRegistration(backend, factory.Alias));
        }

        return new SecurityCompositionSnapshot(new ProviderRegistry(keys, plan.Observability), new SecretProviderRegistry(secrets, plan.Observability),
            store, protector, allocator, plan.TimeProvider, plan.Requirements);
    }
}
