using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>
/// Shared typed-view metadata checks. These are fail-closed preflight checks,
/// not a substitute for authorization or an atomic backend operation.
/// </summary>
internal static class KeyCapabilityPreflight
{
    internal static async ValueTask<KeyCapabilityResolution> ForwardAsync(
        IKeyMetadataResolver metadata,
        LogicalKeyHandle handle,
        KeyKind kind,
        CapabilityId capability,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        KeyDescriptor logical = await LoadLogicalAsync(metadata, handle, kind, cancellationToken).ConfigureAwait(false);
        if (logical.State != LogicalKeyState.Active || !logical.ActiveVersion.HasValue)
        {
            throw new KeyCapabilityException(KeyCapabilityFailure.StateRejected);
        }

        ExactKeyHandle exact = handle.AtVersion(logical.ActiveVersion.Value);
        KeyVersionDescriptor version = await LoadExactAsync(metadata, exact, cancellationToken).ConfigureAwait(false);
        if (version.State != KeyVersionState.Active)
        {
            throw new KeyCapabilityException(KeyCapabilityFailure.StateRejected);
        }

        return RequireCapability(exact, version, capability);
    }

    internal static async ValueTask<KeyCapabilityResolution> HistoricalAsync(
        IKeyMetadataResolver metadata,
        LogicalKeyHandle handle,
        ExactKeyHandle exact,
        KeyKind kind,
        CapabilityId capability,
        CancellationToken cancellationToken)
    {
        if (!exact.IsDefined || !handle.IsDefined)
        {
            throw new ArgumentException("Defined logical and exact handles are required.");
        }

        if (exact.Logical != handle)
        {
            throw new KeyCapabilityException(KeyCapabilityFailure.IdentityMismatch);
        }

        cancellationToken.ThrowIfCancellationRequested();
        KeyDescriptor logical = await LoadLogicalAsync(metadata, handle, kind, cancellationToken).ConfigureAwait(false);
        if (logical.State == LogicalKeyState.Deleted)
        {
            throw new KeyCapabilityException(KeyCapabilityFailure.StateRejected);
        }

        KeyVersionDescriptor version = await LoadExactAsync(metadata, exact, cancellationToken).ConfigureAwait(false);
        if (version.State != KeyVersionState.Active && version.State != KeyVersionState.Retired)
        {
            throw new KeyCapabilityException(KeyCapabilityFailure.StateRejected);
        }

        // An active exact version must match the active version of the logical key.
        if (version.State == KeyVersionState.Active &&
            (logical.State != LogicalKeyState.Active || logical.ActiveVersion != exact.Reference.Version))
        {
            throw new KeyCapabilityException(KeyCapabilityFailure.StateRejected);
        }

        return RequireCapability(exact, version, capability);
    }

    private static async ValueTask<KeyDescriptor> LoadLogicalAsync(
        IKeyMetadataResolver metadata,
        LogicalKeyHandle handle,
        KeyKind kind,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        KeyDescriptor? descriptor = await metadata.FindLogicalAsync(handle, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (descriptor is null)
        {
            throw new KeyCapabilityException(KeyCapabilityFailure.NotFound);
        }

        if (descriptor.ProviderId != handle.ProviderId || descriptor.KeyId != handle.KeyId)
        {
            throw new KeyCapabilityException(KeyCapabilityFailure.IdentityMismatch);
        }

        if (descriptor.Kind != kind)
        {
            throw new KeyCapabilityException(KeyCapabilityFailure.KindMismatch);
        }

        return descriptor;
    }

    private static async ValueTask<KeyVersionDescriptor> LoadExactAsync(
        IKeyMetadataResolver metadata,
        ExactKeyHandle handle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        KeyVersionDescriptor? descriptor = await metadata.FindExactAsync(handle, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (descriptor is null)
        {
            throw new KeyCapabilityException(KeyCapabilityFailure.NotFound);
        }

        if (descriptor.Reference != handle.Reference)
        {
            throw new KeyCapabilityException(KeyCapabilityFailure.IdentityMismatch);
        }

        return descriptor;
    }

    private static KeyCapabilityResolution RequireCapability(
        ExactKeyHandle exact,
        KeyVersionDescriptor descriptor,
        CapabilityId capability)
    {
        if (!descriptor.Capabilities.Contains(capability))
        {
            throw new KeyCapabilityException(KeyCapabilityFailure.CapabilityMissing);
        }

        return new KeyCapabilityResolution(exact, descriptor.Algorithm, capability);
    }
}
