using System.Runtime.Versioning;
using Laveyana.Security.Abstractions.Identifiers;
using Microsoft.Extensions.DependencyInjection;

namespace Laveyana.Security.Maui.NativeKeys;

/// <summary>Explicit Windows TPM signing registration without software fallback.</summary>
[SupportedOSPlatform("windows")]
public static class WindowsTpmSigningServiceCollectionExtensions
{
    /// <summary>Registers one application-owned stable-identity Windows TPM P-256 signer.</summary>
    public static IServiceCollection AddLaveyanaWindowsTpmSigning(
        this IServiceCollection services, ProviderId providerId)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows TPM signing requires Windows.");
        }

        if (!providerId.IsDefined)
        {
            throw new ArgumentException("Provider identity must be defined.", nameof(providerId));
        }

        if (services.Any(item => item.ServiceType == typeof(INativeSigningKeyService)))
        {
            throw new InvalidOperationException("A native signing key service has already been registered.");
        }

        services.AddSingleton<INativeSigningKeyService>(new WindowsTpmSigningKeyService(providerId));
        return services;
    }
}
