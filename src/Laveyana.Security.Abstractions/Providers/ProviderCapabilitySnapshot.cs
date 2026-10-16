using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Providers;

/// <summary>
/// Immutable, bounded provider-wide capability advertisement. Effective authorization
/// also requires compatible key metadata, policy and a backend-side operation check.
/// </summary>
public sealed class ProviderCapabilitySnapshot
{
    /// <summary>Creates a defensive snapshot of at most 64 unique capabilities.</summary>
    public ProviderCapabilitySnapshot(ProviderId providerId, IEnumerable<CapabilityId> capabilities)
    {
        if (!providerId.IsDefined)
        {
            throw new ArgumentException("A defined provider identity is required.", nameof(providerId));
        }

        ArgumentNullException.ThrowIfNull(capabilities);
        CapabilityId[] entries = capabilities.Take(65).ToArray();
        if (entries.Length > 64 || entries.Any(item => !item.IsDefined) ||
            entries.Distinct().Count() != entries.Length)
        {
            throw new ArgumentException("At most 64 unique defined capabilities are permitted.", nameof(capabilities));
        }

        Array.Sort(entries, (left, right) => StringComparer.Ordinal.Compare(left.Value, right.Value));
        ProviderId = providerId;
        Capabilities = Array.AsReadOnly(entries);
    }

    /// <summary>Gets the identity of the advertising provider.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Gets a read-only, sorted snapshot of advertised capabilities.</summary>
    public IReadOnlyList<CapabilityId> Capabilities { get; }

    /// <summary>Tests only provider-wide advertised support, not permission to execute.</summary>
    public bool Supports(CapabilityId capability)
    {
        if (!capability.IsDefined)
        {
            throw new ArgumentException("A defined capability is required.", nameof(capability));
        }

        return Capabilities.Contains(capability);
    }

    /// <summary>Does not expose provider identity in incidental logs.</summary>
    public override string ToString() => "ProviderCapabilitySnapshot";
}
