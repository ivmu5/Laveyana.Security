using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Migration;

/// <summary>How a new provider generation obtains its material; never an implicit raw export.</summary>
public enum ProviderMigrationMode
{
    /// <summary>Allocate new, independent material and migrate dependent data in the application.</summary>
    Regenerate = 1,

    /// <summary>Allow only a provider-to-provider authenticated native transfer.</summary>
    ProviderNativeTransfer = 2
}
