using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Sensitive;

namespace Laveyana.Security.Abstractions.Secrets;

/// <summary>
/// Opaque read-oriented capability bound to one provider and persistent secret ID.
/// It never caches plaintext or grants writes. Material access is callback-scoped.
/// </summary>
public sealed class SecretHandle
{
    private readonly ISecretProvider _provider;

    /// <summary>Creates a read capability for an exact provider/secret identity.</summary>
    public SecretHandle(SecretReference reference, ISecretProvider provider)
    {
        if (!reference.IsDefined)
        {
            throw new ArgumentException("A defined secret reference is required.", nameof(reference));
        }

        ArgumentNullException.ThrowIfNull(provider);
        if (provider.ProviderId != reference.ProviderId)
        {
            throw new ArgumentException("Provider identity must match the reference.", nameof(provider));
        }

        Reference = reference;
        _provider = provider;
    }

    /// <summary>Stable provider/secret reference, not an alias or version.</summary>
    public SecretReference Reference { get; }

    /// <summary>Finds metadata without granting access to secret material.</summary>
    public async ValueTask<SecretDescriptor?> FindAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureProviderIdentity();
        SecretDescriptor? descriptor = await _provider.FindAsync(Reference, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureProviderIdentity();
        if (descriptor is not null && descriptor.Reference != Reference)
        {
            throw new InvalidOperationException("Provider returned a descriptor for another secret.");
        }

        return descriptor;
    }

    /// <summary>
    /// Invokes a synchronous callback with borrowed material and wipes the owned
    /// result even if validation, cancellation or the callback throws. Returns false
    /// only for an absent secret; access-denied and provider errors propagate.
    /// </summary>
    public async ValueTask<bool> UseMaterialAsync(
        SensitiveMaterialAction visitor,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(visitor);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureProviderIdentity();
        using SecretReadResult? result = await _provider.GetAsync(Reference, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureProviderIdentity();
        if (result is null)
        {
            return false;
        }

        if (result.Reference != Reference)
        {
            throw new InvalidOperationException("Provider returned material for another secret.");
        }

        result.UseMaterial(visitor);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureProviderIdentity();
        return true;
    }

    /// <summary>Does not reveal the provider, identity or material in logs.</summary>
    public override string ToString() => "SecretHandle [REDACTED]";

    private void EnsureProviderIdentity()
    {
        if (_provider.ProviderId != Reference.ProviderId)
        {
            throw new InvalidOperationException("Secret provider identity changed.");
        }
    }
}
