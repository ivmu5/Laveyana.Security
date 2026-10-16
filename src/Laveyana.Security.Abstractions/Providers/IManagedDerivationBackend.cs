using Laveyana.Security.Abstractions.Capabilities;
using Laveyana.Security.Abstractions.Handles;

namespace Laveyana.Security.Abstractions.Providers;

/// <summary>Provider-owned HKDF-SHA-256 using an Active managed symmetric derivation key.</summary>
public interface IManagedDerivationBackend : IKeyProviderBackend
{
    /// <summary>Derives a scoped, nonpersistent key; the provider retains control of the input material.</summary>
    ValueTask<DerivedKeyLease> DeriveAsync(LogicalKeyHandle source, DerivationContext context,
        CancellationToken cancellationToken = default);
}
