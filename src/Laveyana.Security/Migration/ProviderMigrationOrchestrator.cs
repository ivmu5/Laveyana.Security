using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Migration;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Providers;
using Laveyana.Security.Providers;

namespace Laveyana.Security.Migration;

/// <summary>One-step-at-a-time provider migration. No implicit aliases, redirects or retry.</summary>
/// <remarks>Caller must authorize each step, durably persist the returned checkpoint using a
/// rollback-resistant compare-and-swap journal and reconcile unknown commit outcomes.
/// This object is not a distributed transaction coordinator.</remarks>
public sealed class ProviderMigrationOrchestrator
{
    private readonly ProviderRegistry _registry;
    private readonly Dictionary<ProviderId, IProviderMigrationDestination> _destinations;

    /// <summary>Registers exact destination adapters independently of ordinary provider routing.</summary>
    public ProviderMigrationOrchestrator(ProviderRegistry registry,
        IEnumerable<IProviderMigrationDestination> destinations)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        ArgumentNullException.ThrowIfNull(destinations);
        _destinations = [];
        foreach (IProviderMigrationDestination destination in destinations)
        {
            if (destination is null || !destination.ProviderId.IsDefined ||
                !_destinations.TryAdd(destination.ProviderId, destination))
            {
                throw new ArgumentException("Migration destination registrations must be distinct and defined.",
                    nameof(destinations));
            }

            _ = _registry.GetRequired(destination.ProviderId);
        }
    }

    /// <summary>Plans against the current exact Active source version, with no mutations.</summary>
    public async ValueTask<ProviderMigrationCheckpoint> PlanAsync(ProviderMigrationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        _ = Destination(request.DestinationProviderId);
        (KeyVersionDescriptor source, KeyKind kind) = await RequireSourceAsync(request, cancellationToken).ConfigureAwait(false);
        await RequireCapabilitiesAsync(request.DestinationProviderId, request.RequiredCapabilities,
            cancellationToken).ConfigureAwait(false);
        return new ProviderMigrationCheckpoint(request, source.Algorithm, kind, ProviderMigrationStage.Planned, null);
    }

    /// <summary>Creates a new target generation. Never automatically retries a mutation.</summary>
    public async ValueTask<ProviderMigrationCheckpoint> PrepareAsync(ProviderMigrationCheckpoint checkpoint,
        CancellationToken cancellationToken = default)
    {
        RequireStage(checkpoint, ProviderMigrationStage.Planned);
        ProviderMigrationRequest request = checkpoint.Request;
        await RequireSourceAsync(request, cancellationToken, checkpoint.Algorithm, checkpoint.Kind).ConfigureAwait(false);
        await RequireCapabilitiesAsync(request.DestinationProviderId, request.RequiredCapabilities,
            cancellationToken).ConfigureAwait(false);
        IProviderMigrationDestination destination = Destination(request.DestinationProviderId);
        KeyDescriptor created;
        if (request.Mode == ProviderMigrationMode.Regenerate)
        {
            created = await destination.CreateRegeneratedAsync(request.DestinationName,
                checkpoint.Algorithm, request.RequiredCapabilities, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            IKeyProviderBackend sourceBackend = _registry.GetRequired(request.Source.ProviderId);
            if (sourceBackend is not IProviderNativeMigrationSource nativeSource ||
                destination is not IProviderNativeMigrationDestination nativeDestination)
            {
                throw new NotSupportedException("Both providers must explicitly support secure native transfer.");
            }

            if (!await nativeDestination.AcceptsSourceAsync(request.Source.ProviderId,
                checkpoint.Algorithm, cancellationToken).ConfigureAwait(false))
            {
                throw new NotSupportedException("Native destination refused this source and algorithm.");
            }

            created = await nativeSource.TransferToAsync(request.Source, nativeDestination,
                request.DestinationName, cancellationToken).ConfigureAwait(false);
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (created is null || created.ProviderId != request.DestinationProviderId ||
            !created.KeyId.IsDefined || created.KeyId == request.Source.KeyId ||
            created.Name != request.DestinationName || created.ActiveVersion is not KeyVersion version ||
            !version.IsDefined || created.Kind != checkpoint.Kind || created.State != LogicalKeyState.Active)
        {
            throw new InvalidOperationException("Destination returned an inconsistent new generation; reconcile before retrying.");
        }

        return checkpoint.Next(ProviderMigrationStage.Prepared,
            new KeyReference(request.DestinationProviderId, created.KeyId, version));
    }

    /// <summary>Revalidates exact target algorithm, material state and required capabilities.</summary>
    public async ValueTask<ProviderMigrationCheckpoint> ValidateAsync(ProviderMigrationCheckpoint checkpoint,
        CancellationToken cancellationToken = default)
    {
        RequireStage(checkpoint, ProviderMigrationStage.Prepared);
        await RequireSourceAsync(checkpoint.Request, cancellationToken, checkpoint.Algorithm, checkpoint.Kind).ConfigureAwait(false);
        await RequireDestinationAsync(checkpoint, requireActive: false, cancellationToken).ConfigureAwait(false);
        return checkpoint.Next(ProviderMigrationStage.Validated);
    }

    /// <summary>Invokes the provider's guarded activation or checks its already-active generation.</summary>
    public async ValueTask<ProviderMigrationCheckpoint> ActivateAsync(ProviderMigrationCheckpoint checkpoint,
        CancellationToken cancellationToken = default)
    {
        RequireStage(checkpoint, ProviderMigrationStage.Validated);
        await RequireSourceAsync(checkpoint.Request, cancellationToken, checkpoint.Algorithm, checkpoint.Kind).ConfigureAwait(false);
        await RequireDestinationAsync(checkpoint, requireActive: false, cancellationToken).ConfigureAwait(false);
        KeyReference target = checkpoint.Destination!.Value;
        KeyDescriptor result = await Destination(checkpoint.Request.DestinationProviderId)
            .ActivatePreparedAsync(target, cancellationToken).ConfigureAwait(false);
        if (result is null || result.ProviderId != target.ProviderId || result.KeyId != target.KeyId ||
            result.State != LogicalKeyState.Active || result.ActiveVersion != target.Version)
        {
            throw new InvalidOperationException("Activation did not preserve the exact prepared target.");
        }

        await RequireDestinationAsync(checkpoint, requireActive: true, cancellationToken).ConfigureAwait(false);
        return checkpoint.Next(ProviderMigrationStage.Activated);
    }

    /// <summary>Accepts an explicit external durable cutover receipt; does not rewrite references.</summary>
    public ProviderMigrationCheckpoint ConfirmApplicationCutover(ProviderMigrationCheckpoint checkpoint,
        MigrationCutoverReceipt receipt)
    {
        RequireStage(checkpoint, ProviderMigrationStage.Activated);
        ArgumentNullException.ThrowIfNull(receipt);
        if (receipt.MigrationId != checkpoint.Request.MigrationId ||
            receipt.Source != checkpoint.Request.Source || receipt.Destination != checkpoint.Destination)
        {
            throw new InvalidOperationException("Application receipt does not match the exact migration identities.");
        }

        return checkpoint.Next(ProviderMigrationStage.ApplicationCutoverConfirmed);
    }

    /// <summary>Delegates retirement only to a source which enforces its own dependency guards.</summary>
    public async ValueTask<ProviderMigrationCheckpoint> RetireSourceAsync(ProviderMigrationCheckpoint checkpoint,
        CancellationToken cancellationToken = default)
    {
        RequireStage(checkpoint, ProviderMigrationStage.ApplicationCutoverConfirmed);
        await RequireDestinationAsync(checkpoint, requireActive: true, cancellationToken).ConfigureAwait(false);
        IProviderMigrationSourceLifecycle source = SourceLifecycle(checkpoint.Request.Source.ProviderId);
        await source.RetireAfterCutoverAsync(checkpoint.Request.Source, checkpoint.Request.MigrationId,
            cancellationToken).ConfigureAwait(false);
        KeyVersionDescriptor? after = await _registry.FindExactAsync(new ExactKeyHandle(checkpoint.Request.Source),
            cancellationToken).ConfigureAwait(false);
        if (after is not null && after.State == KeyVersionState.Active)
        {
            throw new InvalidOperationException("Source still reports Active after retirement; reconcile state.");
        }

        return checkpoint.Next(ProviderMigrationStage.SourceRetired);
    }

    /// <summary>Delegates deletion only to a guard-enforcing source, with no forced-delete fallback.</summary>
    public async ValueTask<ProviderMigrationCheckpoint> DeleteSourceAsync(ProviderMigrationCheckpoint checkpoint,
        CancellationToken cancellationToken = default)
    {
        RequireStage(checkpoint, ProviderMigrationStage.SourceRetired);
        IProviderMigrationSourceLifecycle source = SourceLifecycle(checkpoint.Request.Source.ProviderId);
        await source.DeleteAfterCutoverAsync(checkpoint.Request.Source, checkpoint.Request.MigrationId,
            cancellationToken).ConfigureAwait(false);
        KeyVersionDescriptor? after = await _registry.FindExactAsync(new ExactKeyHandle(checkpoint.Request.Source),
            cancellationToken).ConfigureAwait(false);
        if (after is not null && after.State != KeyVersionState.Deleted)
        {
            throw new InvalidOperationException("Source material still exists after delete; reconcile state.");
        }

        return checkpoint.Next(ProviderMigrationStage.SourceDeleted);
    }

    private IProviderMigrationDestination Destination(ProviderId providerId)
    {
        if (!_destinations.TryGetValue(providerId, out IProviderMigrationDestination? result))
        {
            throw new NotSupportedException("Target provider has no migration destination adapter.");
        }

        return result;
    }

    private IProviderMigrationSourceLifecycle SourceLifecycle(ProviderId providerId) =>
        _registry.GetRequired(providerId) as IProviderMigrationSourceLifecycle ??
        throw new NotSupportedException("Source provider does not implement guarded migration retirement/deletion.");

    private async ValueTask<(KeyVersionDescriptor Version, KeyKind Kind)> RequireSourceAsync(ProviderMigrationRequest request,
        CancellationToken cancellationToken, AlgorithmId? expectedAlgorithm = null, KeyKind? expectedKind = null)
    {
        KeyReference source = request.Source;
        KeyDescriptor? logical = await _registry.FindLogicalAsync(
            new LogicalKeyHandle(source.ProviderId, source.KeyId), cancellationToken).ConfigureAwait(false);
        KeyVersionDescriptor? version = await _registry.FindExactAsync(new ExactKeyHandle(source),
            cancellationToken).ConfigureAwait(false);
        if (logical is null || version is null || logical.Kind == KeyKind.Unspecified ||
            logical.State != LogicalKeyState.Active || logical.ActiveVersion != source.Version ||
            (expectedKind.HasValue && logical.Kind != expectedKind.Value) ||
            version.Reference != source || version.State != KeyVersionState.Active ||
            !version.Algorithm.IsDefined ||
            (expectedAlgorithm.HasValue && version.Algorithm != expectedAlgorithm.Value) ||
            request.RequiredCapabilities.Any(capability => !version.Capabilities.Contains(capability)))
        {
            throw new InvalidOperationException("Exact source version or capabilities changed; abort migration.");
        }

        return (version, logical.Kind);
    }

    private async ValueTask RequireDestinationAsync(ProviderMigrationCheckpoint checkpoint,
        bool requireActive, CancellationToken cancellationToken)
    {
        KeyReference target = checkpoint.Destination ?? throw new InvalidOperationException("No prepared target.");
        KeyDescriptor? logical = await _registry.FindLogicalAsync(new LogicalKeyHandle(target.ProviderId, target.KeyId),
            cancellationToken).ConfigureAwait(false);
        KeyVersionDescriptor? exact = await _registry.FindExactAsync(new ExactKeyHandle(target),
            cancellationToken).ConfigureAwait(false);
        if (logical is null || exact is null || logical.ProviderId != target.ProviderId ||
            logical.KeyId != target.KeyId || logical.Name != checkpoint.Request.DestinationName ||
            logical.Kind != checkpoint.Kind || exact.Reference != target ||
            exact.Algorithm != checkpoint.Algorithm ||
            (exact.State != KeyVersionState.Pending && exact.State != KeyVersionState.Active) ||
            (requireActive && (logical.State != LogicalKeyState.Active ||
                logical.ActiveVersion != target.Version || exact.State != KeyVersionState.Active)) ||
            checkpoint.Request.RequiredCapabilities.Any(capability => !exact.Capabilities.Contains(capability)))
        {
            throw new InvalidOperationException("Exact destination metadata changed or is incompatible.");
        }

        await RequireCapabilitiesAsync(target.ProviderId, checkpoint.Request.RequiredCapabilities,
            cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask RequireCapabilitiesAsync(ProviderId provider,
        IReadOnlyList<CapabilityId> required, CancellationToken cancellationToken)
    {
        ProviderCapabilitySnapshot snapshot = await _registry.GetCapabilitiesAsync(provider,
            cancellationToken).ConfigureAwait(false);
        if (required.Any(capability => !snapshot.Supports(capability)))
        {
            throw new NotSupportedException("Destination does not advertise all required operations.");
        }
    }

    private static void RequireStage(ProviderMigrationCheckpoint checkpoint, ProviderMigrationStage expected)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        if (checkpoint.Stage != expected)
        {
            throw new InvalidOperationException("Migration checkpoint does not permit this transition.");
        }
    }
}
