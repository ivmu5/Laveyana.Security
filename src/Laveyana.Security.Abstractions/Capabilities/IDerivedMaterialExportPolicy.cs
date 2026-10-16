using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Sensitive;

namespace Laveyana.Security.Abstractions.Capabilities;

/// <summary>Opt-in application policy; implementations must authorize export at the current point of use.</summary>
public interface IDerivedMaterialExportPolicy
{
    /// <summary>Returns false unless raw material export is explicitly authorized for the exact source and purpose.</summary>
    bool IsExportAllowed(KeyReference source, string purpose);
}
