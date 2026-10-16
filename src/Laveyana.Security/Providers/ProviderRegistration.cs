using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Providers;

namespace Laveyana.Security.Providers;

/// <summary>
/// One startup registration. An optional runtime alias is independent of persistent identity.
/// </summary>
public sealed class ProviderRegistration
{
    /// <summary>Creates a registration without changing the backend's stable identity.</summary>
    public ProviderRegistration(IKeyProviderBackend backend, ProviderAlias? alias = null)
    {
        ArgumentNullException.ThrowIfNull(backend);
        if (!backend.ProviderId.IsDefined)
        {
            throw new ArgumentException("The backend must declare a defined provider identity.", nameof(backend));
        }

        if (alias.HasValue && !alias.Value.IsDefined)
        {
            throw new ArgumentException("An optional alias must be defined.", nameof(alias));
        }

        Backend = backend;
        ProviderId = backend.ProviderId;
        Alias = alias;
    }

    /// <summary>Gets the captured persistent identity.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Gets the optional runtime-only lookup alias.</summary>
    public ProviderAlias? Alias { get; }

    /// <summary>Gets the registered backend; its identity is checked on every routing operation.</summary>
    public IKeyProviderBackend Backend { get; }
}
