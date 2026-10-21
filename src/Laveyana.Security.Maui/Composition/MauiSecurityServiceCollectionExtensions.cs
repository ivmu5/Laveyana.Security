using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Maui.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Maui.Storage;

namespace Laveyana.Security.Maui.Composition;

/// <summary>Explicit, opt-in MAUI SecureStorage registration for Laveyana secret management.</summary>
public static class MauiSecurityServiceCollectionExtensions
{
    /// <summary>
    /// Registers a single app-scoped provider. The app must use the same stable provider ID
    /// across launches. Pass a specific ISecureStorage for tests or to override MAUI Default.
    /// Call this before AddSecurity(... UseSecretProvider&lt;MauiSecureStorageSecretProvider&gt;).
    /// </summary>
    public static IServiceCollection AddLaveyanaMauiSecureStorage(
        this IServiceCollection services, ProviderId providerId, ISecureStorage? storage = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (!providerId.IsDefined)
        {
            throw new ArgumentException("A stable provider ID is required.", nameof(providerId));
        }

        if (services.Any(item => item.ServiceType == typeof(MauiSecureStorageSecretProvider)))
        {
            throw new InvalidOperationException("MAUI secure storage provider is already registered.");
        }

        services.AddSingleton<MauiSecureStorageSecretProvider>(
            _ => new MauiSecureStorageSecretProvider(providerId, storage ?? SecureStorage.Default));
        return services;
    }
}
