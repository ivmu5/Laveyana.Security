using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Migration;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Software;

namespace Laveyana.Security.Migration;

/// <summary>Explicit regeneration-only adapter for protected software-managed symmetric keys.</summary>
public sealed class SoftwareMigrationDestination : IProviderMigrationDestination
{
    private readonly SoftwareKeyProviderBackend _backend;

    /// <summary>Wraps an existing key manager without changing the registered backend.</summary>
    public SoftwareMigrationDestination(SoftwareKeyProviderBackend backend) =>
        _backend = backend ?? throw new ArgumentNullException(nameof(backend));

    /// <summary>Authoritative target provider identity.</summary>
    public ProviderId ProviderId => _backend.ProviderId;

    /// <summary>Creates new random material and a new KeyId, never copying source material.</summary>
    public ValueTask<KeyDescriptor> CreateRegeneratedAsync(KeyName name, AlgorithmId algorithm,
        IReadOnlyList<CapabilityId> capabilities, CancellationToken cancellationToken = default) =>
        _backend.CreateAsync(name, algorithm, capabilities, cancellationToken);

    /// <summary>Only accepts the exact already-active software key version.</summary>
    public async ValueTask<KeyDescriptor> ActivatePreparedAsync(KeyReference prepared,
        CancellationToken cancellationToken = default)
    {
        if (!prepared.IsDefined || prepared.ProviderId != ProviderId)
        {
            throw new ArgumentException("Prepared version belongs to another provider.", nameof(prepared));
        }

        KeyDescriptor descriptor = await _backend.FindLogicalAsync(
            new LogicalKeyHandle(prepared.ProviderId, prepared.KeyId), cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Prepared destination no longer exists.");
        if (descriptor.ProviderId != ProviderId || descriptor.KeyId != prepared.KeyId ||
            descriptor.State != LogicalKeyState.Active || descriptor.ActiveVersion != prepared.Version)
        {
            throw new InvalidOperationException("Prepared destination is not the expected Active version.");
        }

        return descriptor;
    }
}
