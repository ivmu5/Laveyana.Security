using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;

namespace Laveyana.Security.Protection;

/// <summary>Explicit registration of one historical, read-only protector generation.</summary>
public sealed class HistoricalProtectorRegistration
{
    /// <summary>Constructs a trusted legacy or blocked compromised generation.</summary>
    public HistoricalProtectorRegistration(IKeyStoreProtector protector, HistoricalProtectorStatus status)
    {
        Protector = protector ?? throw new ArgumentNullException(nameof(protector));
        if (!protector.CurrentReference.IsDefined || !Enum.IsDefined(status))
        {
            throw new ArgumentException("A historical registration needs a defined reference and status.");
        }

        Status = status;
    }

    /// <summary>Gets the protector used only to read its own historical reference.</summary>
    public IKeyStoreProtector Protector { get; }

    /// <summary>Gets the declared trust status of the historical generation.</summary>
    public HistoricalProtectorStatus Status { get; }
}
