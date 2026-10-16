using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;

namespace Laveyana.Security.Protection;

/// <summary>Trust status of a historic at-rest protector generation.</summary>
public enum HistoricalProtectorStatus
{
    /// <summary>Allowed to authenticate existing envelopes, never to create new ones.</summary>
    LegacyReadOnly = 1,

    /// <summary>Potentially exposed protection material: ordinary re-protection is forbidden.</summary>
    Compromised = 2
}
