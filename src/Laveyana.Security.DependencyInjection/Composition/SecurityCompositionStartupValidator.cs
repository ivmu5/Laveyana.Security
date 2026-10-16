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

/// <summary>One-time startup check; not a worker and does not rotate or persist keys.</summary>
internal sealed class SecurityCompositionStartupValidator : IHostedService
{
    private readonly SecurityCompositionSnapshot _snapshot;

    public SecurityCompositionStartupValidator(SecurityCompositionSnapshot snapshot) => _snapshot = snapshot;

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken) =>
        _snapshot.ValidateCapabilitiesAsync(cancellationToken).AsTask();

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
