using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;

namespace Laveyana.Security.Protection;

/// <summary>Explicit trust classification for one persisted envelope generation.</summary>
public enum ProtectorGenerationClassification
{
    /// <summary>No registered trusted reader.</summary>
    Unknown = 0,
    /// <summary>The only generation allowed for new encryption.</summary>
    Current = 1,
    /// <summary>Historical, authenticated-read-only generation.</summary>
    LegacyReadOnly = 2,
    /// <summary>Known potentially compromised generation; ordinary reading is blocked.</summary>
    Compromised = 3
}
