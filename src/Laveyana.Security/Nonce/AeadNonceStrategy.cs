using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Nonce;
using Laveyana.Security.Abstractions.Storage;

namespace Laveyana.Security.Nonce;

/// <summary>Policy output. ProviderManaged never issues a nonce for local encryption.</summary>
internal enum AeadNonceStrategy
{
    Randomized = 1,
    RollbackProtectedDeterministic = 2,
    ProviderManaged = 3,
}
