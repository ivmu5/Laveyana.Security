using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Secrets;

namespace Laveyana.Security.Secrets;

/// <summary>One immutable configuration entry for a read-oriented secret backend.</summary>
public sealed class SecretProviderRegistration
{
    /// <summary>Captures the stable identity and optional runtime alias.</summary>
    public SecretProviderRegistration(ISecretProvider backend, ProviderAlias? alias = null)
    {
        ArgumentNullException.ThrowIfNull(backend);
        if (!backend.ProviderId.IsDefined)
        {
            throw new ArgumentException("A defined provider ID is required.", nameof(backend));
        }

        if (alias.HasValue && !alias.Value.IsDefined)
        {
            throw new ArgumentException("An optional alias must be defined.", nameof(alias));
        }

        Backend = backend;
        ProviderId = backend.ProviderId;
        Alias = alias;
    }

    /// <summary>Immutable configured provider identity.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Optional case-sensitive runtime alias.</summary>
    public ProviderAlias? Alias { get; }

    /// <summary>Registered backend; its identity is rechecked when routed.</summary>
    public ISecretProvider Backend { get; }
}
