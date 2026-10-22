using System.Runtime.Versioning;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Maui.NativeKeys;
using Microsoft.Extensions.DependencyInjection;

namespace Laveyana.Security.Maui.Apple;

/// <summary>Explicit Apple Secure Enclave signing registration without fallback.</summary>
[SupportedOSPlatform("ios13.0")]
[SupportedOSPlatform("maccatalyst15.0")]
public static class AppleSecureEnclaveServiceCollectionExtensions
{
    /// <summary>Registers one signer using a caller-persisted provider identity.</summary>
    public static IServiceCollection AddLaveyanaAppleSecureEnclaveSigning(
        this IServiceCollection services, ProviderId providerId)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (!OperatingSystem.IsIOS() && !OperatingSystem.IsMacCatalyst())
        {
            throw new PlatformNotSupportedException("Secure Enclave requires iOS or Mac Catalyst.");
        }

        if (!providerId.IsDefined)
        {
            throw new ArgumentException("Provider ID must be defined.", nameof(providerId));
        }

        if (services.Any(item => item.ServiceType == typeof(INativeSigningKeyService)))
        {
            throw new InvalidOperationException("A native signing key service is already registered.");
        }

        services.AddSingleton<INativeSigningKeyService>(
            new AppleSecureEnclaveSigningKeyService(providerId));
        return services;
    }
}
