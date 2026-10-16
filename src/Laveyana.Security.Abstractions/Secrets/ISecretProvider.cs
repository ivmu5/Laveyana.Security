using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;

namespace Laveyana.Security.Abstractions.Secrets;

/// <summary>
/// Minimal read-only extension point for provider-owned secrets. Providers enforce
/// authorization and access policy on every GetAsync call, not only on FindAsync.
/// </summary>
/// <remarks>
/// A null result means absence, not permission denial or transport failure. A
/// successful GetAsync transfers ownership of its result to the caller. Secrets
/// cannot be enumerated or written through this interface. No universal version
/// number is implied by the reference or returned material.
/// </remarks>
public interface ISecretProvider
{
    /// <summary>Stable, persistent provider identity, not a runtime alias.</summary>
    ProviderId ProviderId { get; }

    /// <summary>Gets a metadata snapshot or null if the secret does not exist.</summary>
    ValueTask<SecretDescriptor?> FindAsync(
        SecretReference reference,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets an owned, disposable secret read result or null if absent. The provider
    /// must deny unauthorized reads instead of returning material based on metadata.
    /// </summary>
    ValueTask<SecretReadResult?> GetAsync(
        SecretReference reference,
        CancellationToken cancellationToken = default);
}
