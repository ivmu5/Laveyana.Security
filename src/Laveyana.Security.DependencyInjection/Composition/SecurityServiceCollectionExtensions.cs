using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Nonce;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Providers;
using Laveyana.Security.Diagnostics;
using Laveyana.Security.Secrets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Laveyana.Security.DependencyInjection.Composition;

/// <summary>Opt-in dependency injection without platform guessing or implicit key ownership.</summary>
public static class SecurityServiceCollectionExtensions
{
    /// <summary>
    /// Adds a single, immutable composition; registration errors fail immediately and
    /// factory identity errors fail upon resolution / host startup.
    /// </summary>
    public static IServiceCollection AddSecurity(this IServiceCollection services,
        Action<SecurityCompositionBuilder> configure)
        => AddSecurityCore(services, configure, requireDefaults: false);

    /// <summary>
    /// Safe defaults require an explicitly selected authenticated protector. This
    /// never creates a plaintext store, software backend or background worker.
    /// </summary>
    public static IServiceCollection AddSecurityDefaults(this IServiceCollection services,
        Action<SecurityCompositionBuilder>? configure = null)
        => AddSecurityCore(services, configure ?? (_ => { }), requireDefaults: true);

    /// <summary>Convenience safe preset using the caller-selected, already initialized protector.</summary>
    public static IServiceCollection AddSecurityDefaults(this IServiceCollection services,
        IKeyStoreProtector protector, Action<SecurityCompositionBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(protector);
        return AddSecurityCore(services, builder =>
        {
            builder.UseProtector(protector);
            configure?.Invoke(builder);
        }, requireDefaults: true);
    }

    private static IServiceCollection AddSecurityCore(IServiceCollection services,
        Action<SecurityCompositionBuilder> configure, bool requireDefaults)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);
        if (services.Any(item => item.ServiceType == typeof(SecurityCompositionSnapshot)))
        {
            throw new InvalidOperationException("Laveyana.Security composition may be registered only once.");
        }

        SecurityCompositionBuilder builder = new(services);
        configure(builder);
        SecurityCompositionBuilder.SecurityCompositionPlan plan = builder.Seal(requireDefaults);
        if (plan.Store is not null && services.Any(item => item.ServiceType == typeof(IKeyStore)))
        {
            throw new InvalidOperationException("The selected store conflicts with an existing IKeyStore registration.");
        }

        if (plan.Protector is not null && services.Any(item => item.ServiceType == typeof(IKeyStoreProtector)))
        {
            throw new InvalidOperationException("The selected protector conflicts with an existing IKeyStoreProtector registration.");
        }

        if (plan.NonceAllocator is not null &&
            services.Any(item => item.ServiceType == typeof(IRollbackProtectedNonceAllocator)))
        {
            throw new InvalidOperationException("The allocator conflicts with an existing service registration.");
        }

        if (services.Any(item => item.ServiceType == typeof(ProviderRegistry) ||
            item.ServiceType == typeof(SecretProviderRegistry) ||
            item.ServiceType == typeof(IKeyMetadataResolver)))
        {
            throw new InvalidOperationException("Conflicting existing security registry registration.");
        }

        if (plan.Store is not null)
        {
            services.AddSingleton(plan.Store);
        }

        if (plan.Protector is not null)
        {
            services.AddSingleton(plan.Protector);
        }

        if (plan.NonceAllocator is not null)
        {
            services.AddSingleton(plan.NonceAllocator);
        }

        if (plan.Observability is not null)
        {
            if (services.Any(item => item.ServiceType == typeof(SecurityObservability)))
            {
                throw new InvalidOperationException("Conflicting observability registration.");
            }

            services.AddSingleton(plan.Observability);
        }

        services.AddSingleton(sp => SecurityCompositionSnapshot.Create(sp, plan));
        services.AddSingleton(sp => sp.GetRequiredService<SecurityCompositionSnapshot>().KeyProviders);
        services.AddSingleton(sp => sp.GetRequiredService<SecurityCompositionSnapshot>().SecretProviders);
        services.AddSingleton<IKeyMetadataResolver>(sp => sp.GetRequiredService<ProviderRegistry>());
        services.AddSingleton<IHostedService, SecurityCompositionStartupValidator>();
        return services;
    }
}
