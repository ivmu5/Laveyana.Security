using System.Runtime.Versioning;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Maui.NativeKeys;
using Microsoft.Extensions.DependencyInjection;

namespace Laveyana.Security.Maui.Android;

/// <summary>Explicit Android hardware-signing DI integration.</summary>
[SupportedOSPlatform("android31.0")]
public static class AndroidKeystoreServiceCollectionExtensions
{
    /// <summary>Registers one persistent provider identity with no software fallback.</summary>
    public static IServiceCollection AddLaveyanaAndroidKeystoreSigning(
        this IServiceCollection services, ProviderId providerId)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (!OperatingSystem.IsAndroidVersionAtLeast(31))
        {
            throw new PlatformNotSupportedException("Android API 31 or higher is required.");
        }

        if (!providerId.IsDefined)
        {
            throw new ArgumentException("Provider ID must be defined.", nameof(providerId));
        }

        if (services.Any(item => item.ServiceType == typeof(INativeSigningKeyService)))
        {
            throw new InvalidOperationException("A native signing provider is already registered.");
        }

        services.AddSingleton<INativeSigningKeyService>(
            new AndroidKeystoreSigningKeyService(providerId));
        return services;
    }
}
