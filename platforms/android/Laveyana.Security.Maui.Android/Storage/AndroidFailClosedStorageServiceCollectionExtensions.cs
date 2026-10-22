using Android.App;
using Android.Content;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Maui.Storage;
using Microsoft.Extensions.DependencyInjection;
using System.Runtime.Versioning;

namespace Laveyana.Security.Maui.Android.Storage;

/// <summary>Explicit, opt-in DI registration for fail-closed Android encrypted preferences.</summary>
[SupportedOSPlatform("android31.0")]
public static class AndroidFailClosedStorageServiceCollectionExtensions
{
    /// <summary>
    /// Registers the existing secret provider against isolated Android encrypted
    /// preferences, not MAUI SecureStorage.Default. The application's standard
    /// AddSecurity(...UseSecretProvider...) registration is still required.
    /// </summary>
    public static IServiceCollection AddLaveyanaAndroidFailClosedSecureStorage(
        this IServiceCollection services, ProviderId providerId, Context? context = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (!OperatingSystem.IsAndroidVersionAtLeast(31))
        {
            throw new PlatformNotSupportedException("Android API 31 or later is required.");
        }

        if (!providerId.IsDefined)
        {
            throw new ArgumentException("A stable provider ID is required.", nameof(providerId));
        }

        if (services.Any(item => item.ServiceType == typeof(MauiSecureStorageSecretProvider)))
        {
            throw new InvalidOperationException("A MAUI secret provider is already registered.");
        }

        services.AddSingleton<MauiSecureStorageSecretProvider>(_ =>
            new MauiSecureStorageSecretProvider(providerId,
                new AndroidFailClosedSecureStorage(providerId, context ?? Application.Context)));
        return services;
    }
}
