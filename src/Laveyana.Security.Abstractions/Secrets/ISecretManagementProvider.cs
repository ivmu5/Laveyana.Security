using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Sensitive;

namespace Laveyana.Security.Abstractions.Secrets;

/// <summary>
/// Optional management extension. A read-only secret provider need not implement it.
/// </summary>
/// <remarks>
/// Management authorization and atomicity belong to the provider. SetAsync must
/// finish using borrowed material before its returned task completes; it must not
/// retain the lease. The caller retains ownership and disposes it. These methods
/// do not prescribe a universal secret version or key-like rotation lifecycle.
/// </remarks>
public interface ISecretManagementProvider : ISecretProvider
{
    /// <summary>Creates or replaces material according to provider-defined policy.</summary>
    ValueTask SetAsync(
        SecretReference reference,
        SensitiveMaterialLease material,
        CancellationToken cancellationToken = default);

    /// <summary>Deletes a secret according to provider-defined policy.</summary>
    ValueTask DeleteAsync(
        SecretReference reference,
        CancellationToken cancellationToken = default);
}
