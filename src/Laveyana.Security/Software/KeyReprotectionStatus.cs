using System.Security.Cryptography;
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Models;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Abstractions.Sensitive;
using Laveyana.Security.Abstractions.Storage;
using Laveyana.Security.Protection;

namespace Laveyana.Security.Software;

/// <summary>Definitive outcome of one explicit at-rest protection migration.</summary>
public enum KeyReprotectionStatus
{
    /// <summary>Metadata and every extant material envelope were committed under the current generation.</summary>
    Reprotected = 1,
    /// <summary>All envelopes already use the current generation; no mutation was performed.</summary>
    AlreadyCurrent = 2
}
