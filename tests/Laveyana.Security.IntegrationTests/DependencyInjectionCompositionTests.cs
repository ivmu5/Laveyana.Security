using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Abstractions.Secrets;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Secrets;
using Laveyana.Security.DependencyInjection.Composition;
using Laveyana.Security.Providers;
using Laveyana.Security.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NUnit.Framework;

namespace Laveyana.Security.IntegrationTests;

/// <summary>Cross-assembly security composition and container lifetime gates.</summary>
[TestFixture]
internal sealed class DependencyInjectionCompositionTests
{
    [Test]
    public void ObservabilityIsExplicitAndRegisteredAsTheExactSingleton()
    {
        ServiceCollection defaultServices = [];
        defaultServices.AddSecurity(_ => { });
        using ServiceProvider without = defaultServices.BuildServiceProvider();
        Assert.That(without.GetService<SecurityObservability>(), Is.Null);

        SecurityObservability observer = new();
        ServiceCollection services = [];
        services.AddSecurity(builder => builder.WithObservability(observer));
        using ServiceProvider container = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true
        });
        Assert.That(container.GetRequiredService<SecurityObservability>(), Is.SameAs(observer));
        Assert.That(container.GetRequiredService<SecurityCompositionSnapshot>().SecretProviders.Count, Is.Zero);

        ServiceCollection duplicates = [];
        Assert.Throws<InvalidOperationException>(() => duplicates.AddSecurity(builder =>
            builder.WithObservability(observer).WithObservability(observer)));
    }

    [Test]
    public void ManualAndDiProviderRoutesHaveTheSameIdentity()
    {
        KeyBackend backend = new(ProviderId.New());
        ProviderAlias alias = new("primary");
        ProviderRegistry manual = new([new ProviderRegistration(backend, alias)]);
        ServiceCollection services = [];
        services.AddSecurity(builder => builder.UseKeyProvider(backend, alias));
        using ServiceProvider container = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true
        });

        ProviderRegistry composed = container.GetRequiredService<ProviderRegistry>();
        Assert.That(composed.GetRequired(backend.ProviderId), Is.SameAs(manual.GetRequired(backend.ProviderId)));
        Assert.That(composed.ResolveAlias(alias), Is.EqualTo(manual.ResolveAlias(alias)));
        Assert.That(container.GetRequiredService<SecurityCompositionSnapshot>().KeyProviders, Is.SameAs(composed));
    }

    [Test]
    public void SecretRegistryIsSingletonAndDoesNotRequireManagement()
    {
        SecretBackend secret = new(ProviderId.New());
        ServiceCollection services = [];
        services.AddSecurity(builder => builder.UseSecretProvider(secret, new ProviderAlias("secrets")));
        using ServiceProvider container = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true
        });
        SecretProviderRegistry registry = container.GetRequiredService<SecretProviderRegistry>();
        Assert.That(registry.GetRequired(secret.ProviderId), Is.SameAs(secret));
        Assert.That(registry, Is.SameAs(container.GetRequiredService<SecretProviderRegistry>()));
    }

    [Test]
    public void DefaultsWithoutExplicitProtectorAreRejected()
    {
        ServiceCollection services = [];
        Assert.Throws<InvalidOperationException>(() => services.AddSecurityDefaults());
        Assert.That(services, Is.Empty);
    }

    [Test]
    public void ExplicitProtectorEnablesSafeEmptyPresetWithoutCreatingAStore()
    {
        ServiceCollection services = [];
        Protector protector = new();
        services.AddSecurityDefaults(protector);
        using ServiceProvider container = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true
        });
        SecurityCompositionSnapshot snapshot = container.GetRequiredService<SecurityCompositionSnapshot>();
        Assert.That(snapshot.Protector, Is.SameAs(protector));
        Assert.That(snapshot.Store, Is.Null);
        Assert.That(snapshot.KeyProviders.Count, Is.Zero);
    }

    [Test]
    public void SoftwareBackendRequiresBothStoreAndProtector()
    {
        ServiceCollection services = [];
        Assert.Throws<InvalidOperationException>(() => services.AddSecurity(builder =>
            builder.UseSoftwareProvider(ProviderId.New())));
        Assert.That(services, Is.Empty);
    }

    [Test]
    public void DuplicateProviderIdentityFailsBeforeServiceProviderConstruction()
    {
        KeyBackend backend = new(ProviderId.New());
        ServiceCollection services = [];
        Assert.Throws<InvalidOperationException>(() => services.AddSecurity(builder =>
        {
            builder.UseKeyProvider(backend);
            builder.UseKeyProvider(backend);
        }));
    }

    [Test]
    public void AliasCollisionsAcrossKeyAndSecretRegistriesFail()
    {
        ServiceCollection services = [];
        Assert.Throws<InvalidOperationException>(() => services.AddSecurity(builder =>
        {
            builder.UseKeyProvider(new KeyBackend(ProviderId.New()), new ProviderAlias("shared"));
            builder.UseSecretProvider(new SecretBackend(ProviderId.New()), new ProviderAlias("shared"));
        }));
    }

    [Test]
    public void ConfigurationIsFrozenAfterRegistration()
    {
        ServiceCollection services = [];
        SecurityCompositionBuilder? retained = null;
        services.AddSecurity(builder => retained = builder);
        Assert.That(retained, Is.Not.Null);
        Assert.Throws<InvalidOperationException>(() => retained!.UseKeyProvider(new KeyBackend(ProviderId.New())));
    }

    [Test]
    public void ScopedBackendCannotBeCapturedBySingletonRegistry()
    {
        ServiceCollection services = [];
        services.AddScoped<KeyBackend>(_ => new KeyBackend(ProviderId.New()));
        Assert.Throws<InvalidOperationException>(() => services.AddSecurity(builder =>
            builder.UseKeyProvider<KeyBackend>(ProviderId.New())));
    }

    [Test]
    public void DuplicateTypedRegistrationsAreRejected()
    {
        ServiceCollection services = [];
        services.AddSingleton(new KeyBackend(ProviderId.New()));
        services.AddSingleton(new KeyBackend(ProviderId.New()));
        Assert.Throws<InvalidOperationException>(() => services.AddSecurity(builder =>
            builder.UseKeyProvider<KeyBackend>(ProviderId.New())));
    }

    [Test]
    public void TypedBackendWrongIdFailsOnResolution()
    {
        KeyBackend backend = new(ProviderId.New());
        ServiceCollection services = [];
        services.AddSingleton(backend);
        services.AddSecurity(builder => builder.UseKeyProvider<KeyBackend>(ProviderId.New()));
        using ServiceProvider container = services.BuildServiceProvider();
        Assert.Throws<InvalidOperationException>(() => container.GetRequiredService<ProviderRegistry>());
    }

    [Test]
    public void SingletonTypedBackendIsReusedAcrossScopes()
    {
        KeyBackend backend = new(ProviderId.New());
        ServiceCollection services = [];
        services.AddSingleton(backend);
        services.AddSecurity(builder => builder.UseKeyProvider<KeyBackend>(backend.ProviderId));
        using ServiceProvider container = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true
        });
        using IServiceScope first = container.CreateScope();
        using IServiceScope second = container.CreateScope();
        Assert.That(first.ServiceProvider.GetRequiredService<ProviderRegistry>(),
            Is.SameAs(second.ServiceProvider.GetRequiredService<ProviderRegistry>()));
    }

    [Test]
    public async Task StartupValidationRejectsMissingAdvertisedCapability()
    {
        KeyBackend backend = new(ProviderId.New());
        ServiceCollection services = [];
        services.AddSecurity(builder => builder.UseKeyProvider(backend)
            .RequireCapability(backend.ProviderId, WellKnownCapabilities.Mac));
        using ServiceProvider container = services.BuildServiceProvider();
        IHostedService startup = container.GetServices<IHostedService>().Single();
        Assert.ThrowsAsync<InvalidOperationException>(async () => await startup.StartAsync(CancellationToken.None));
        Assert.That(backend.CapabilityReads, Is.EqualTo(1));
        await startup.StopAsync(CancellationToken.None);
    }

    [Test]
    public async Task CustomCapabilityRequirementPassesWhenBackendAdvertisesIt()
    {
        CapabilityId custom = new("custom-capability");
        KeyBackend backend = new(ProviderId.New()) { Advertised = [custom] };
        ServiceCollection services = [];
        services.AddSecurity(builder => builder.UseKeyProvider(backend)
            .RequireCapability(backend.ProviderId, custom));
        using ServiceProvider container = services.BuildServiceProvider();
        SecurityCompositionSnapshot snapshot = container.GetRequiredService<SecurityCompositionSnapshot>();
        await snapshot.ValidateCapabilitiesAsync();
        Assert.That(backend.CapabilityReads, Is.EqualTo(1));
    }

    [Test]
    public void IdentityMutationAfterRegistrationFailsOnResolution()
    {
        KeyBackend backend = new(ProviderId.New());
        ServiceCollection services = [];
        services.AddSecurity(builder => builder.UseKeyProvider(backend));
        backend.ProviderId = ProviderId.New();
        using ServiceProvider container = services.BuildServiceProvider();
        Assert.Throws<InvalidOperationException>(() => container.GetRequiredService<ProviderRegistry>());
    }

    [Test]
    public async Task StartupValidationChecksOperationImplementationAsWellAsAdvertisement()
    {
        KeyBackend backend = new(ProviderId.New()) { Advertised = [WellKnownCapabilities.Encrypt] };
        ServiceCollection services = [];
        services.AddSecurity(builder => builder.UseKeyProvider(backend)
            .RequireCapability(backend.ProviderId, WellKnownCapabilities.Encrypt));
        using ServiceProvider container = services.BuildServiceProvider();
        SecurityCompositionSnapshot snapshot = container.GetRequiredService<SecurityCompositionSnapshot>();
        Assert.ThrowsAsync<InvalidOperationException>(async () => await snapshot.ValidateCapabilitiesAsync());
    }

    [Test]
    public void UnregisteredCapabilityRequirementsFailAtConfiguration()
    {
        ServiceCollection services = [];
        Assert.Throws<InvalidOperationException>(() => services.AddSecurity(builder =>
            builder.RequireCapability(ProviderId.New(), WellKnownCapabilities.Encrypt)));
    }

    [Test]
    public void TypedProtectorMustBeSingleton()
    {
        ServiceCollection services = [];
        services.AddTransient<Protector>();
        Assert.Throws<InvalidOperationException>(() => services.AddSecurity(builder =>
            builder.UseProtector<Protector>()));
    }

    [Test]
    public void ProtectorIsNeverInventedForReadOnlyProviderComposition()
    {
        ServiceCollection services = [];
        services.AddSecurity(builder => builder.UseSecretProvider(new SecretBackend(ProviderId.New())));
        using ServiceProvider container = services.BuildServiceProvider();
        SecurityCompositionSnapshot snapshot = container.GetRequiredService<SecurityCompositionSnapshot>();
        Assert.That(snapshot.Protector, Is.Null);
        Assert.That(container.GetService<IKeyStoreProtector>(), Is.Null);
    }

    [Test]
    public void MoreThanOneCompositionIsRejected()
    {
        ServiceCollection services = [];
        services.AddSecurity(_ => { });
        Assert.Throws<InvalidOperationException>(() => services.AddSecurity(_ => { }));
    }

    [Test]
    public async Task EmptyHostValidatorDoesNotStartAnyWorker()
    {
        ServiceCollection services = [];
        services.AddSecurity(_ => { });
        using ServiceProvider container = services.BuildServiceProvider();
        IHostedService[] hosted = container.GetServices<IHostedService>().ToArray();
        Assert.That(hosted, Has.Length.EqualTo(1));
        await hosted[0].StartAsync(CancellationToken.None);
        await hosted[0].StopAsync(CancellationToken.None);
    }

    private sealed class KeyBackend(ProviderId providerId) : IKeyProviderBackend
    {
        public ProviderId ProviderId { get; set; } = providerId;
        public CapabilityId[] Advertised { get; set; } = [];
        public int CapabilityReads { get; private set; }

        public ValueTask<ProviderCapabilitySnapshot> GetCapabilitiesAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CapabilityReads++;
            return ValueTask.FromResult(new ProviderCapabilitySnapshot(ProviderId, Advertised));
        }

        public ValueTask<KeyDescriptor?> FindLogicalAsync(LogicalKeyHandle handle,
            CancellationToken cancellationToken = default) => ValueTask.FromResult<KeyDescriptor?>(null);

        public ValueTask<KeyVersionDescriptor?> FindExactAsync(ExactKeyHandle handle,
            CancellationToken cancellationToken = default) => ValueTask.FromResult<KeyVersionDescriptor?>(null);
    }

    private sealed class SecretBackend(ProviderId providerId) : ISecretProvider
    {
        public ProviderId ProviderId { get; } = providerId;
        public ValueTask<SecretDescriptor?> FindAsync(SecretReference reference,
            CancellationToken cancellationToken = default) => ValueTask.FromResult<SecretDescriptor?>(null);

        public ValueTask<SecretReadResult?> GetAsync(SecretReference reference,
            CancellationToken cancellationToken = default) => ValueTask.FromResult<SecretReadResult?>(null);
    }

    private sealed class Protector : IKeyStoreProtector
    {
        public ProtectorReference CurrentReference { get; } = new("IntegrationTest", 1);

        public ValueTask<ProtectedStoreEnvelope> ProtectAsync(SensitiveMaterialLease plaintext,
            ProtectionPurpose purpose, ReadOnlyMemory<byte> authenticatedContext,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("Test protector never persists data.");

        public ValueTask<SensitiveMaterialLease> UnprotectAsync(ProtectedStoreEnvelope envelope,
            ProtectionPurpose expectedPurpose, ReadOnlyMemory<byte> authenticatedContext,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("Test protector never decrypts data.");
    }
}
