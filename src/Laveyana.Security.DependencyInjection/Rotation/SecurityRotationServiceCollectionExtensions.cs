using Laveyana.Security.DependencyInjection.Composition;
using Laveyana.Security.Rotation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Laveyana.Security.DependencyInjection.Rotation;

/// <summary>Explicit background rotation opt-in; never called by AddSecurity defaults.</summary>
public static class SecurityRotationServiceCollectionExtensions
{
    /// <summary>
    /// Adds exactly one worker with a caller-supplied durable, atomic work source.
    /// The source remains application-owned; no implicit persistent scheduler exists.
    /// </summary>
    public static IServiceCollection AddSecurityRotationWorker(this IServiceCollection services,
        IRotationWorkSource source, TimeSpan pollInterval)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(source);
        if (pollInterval < TimeSpan.FromMilliseconds(100) || pollInterval > TimeSpan.FromDays(1))
        {
            throw new ArgumentOutOfRangeException(nameof(pollInterval));
        }

        if (!services.Any(x => x.ServiceType == typeof(SecurityCompositionSnapshot)))
        {
            throw new InvalidOperationException("AddSecurity must be configured before its rotation worker.");
        }

        if (services.Any(x => x.ServiceType == typeof(RotationWorker) ||
            x.ServiceType == typeof(RotationEngine) || x.ServiceType == typeof(IRotationWorkSource)))
        {
            throw new InvalidOperationException("A rotation worker is already configured or registrations conflict.");
        }

        services.AddSingleton<IRotationWorkSource>(source);
        services.AddSingleton<RotationEngine>(sp => new RotationEngine(
            sp.GetRequiredService<SecurityCompositionSnapshot>().KeyProviders,
            sp.GetRequiredService<SecurityCompositionSnapshot>().TimeProvider));
        services.AddSingleton(sp => new RotationWorker(sp.GetRequiredService<IRotationWorkSource>(),
            sp.GetRequiredService<RotationEngine>(),
            sp.GetRequiredService<SecurityCompositionSnapshot>(), pollInterval));
        services.AddSingleton<IHostedService>(sp => sp.GetRequiredService<RotationWorker>());
        return services;
    }
}
