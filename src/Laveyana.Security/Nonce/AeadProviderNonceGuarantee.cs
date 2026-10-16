using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Nonce;
using Laveyana.Security.Abstractions.Storage;

namespace Laveyana.Security.Nonce;

/// <summary>Explicit verified provider guarantees, not untrusted provider capability strings.</summary>
internal enum AeadProviderNonceGuarantee
{
    None = 0,
    OwnsFreshKeyNonceLifecycle = 1,
    OwnsNonceLifecycleIncludingImportedHistory = 2,
}
