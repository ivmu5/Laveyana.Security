using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Nonce;
using Laveyana.Security.Abstractions.Storage;

namespace Laveyana.Security.Nonce;

/// <summary>The current restore/reconciliation status of an exact key generation.</summary>
internal enum AeadRestoreState
{
    Clean = 0,
    KnownRestoredGeneration = 1,
}
