using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Nonce;
using Laveyana.Security.Abstractions.Storage;

namespace Laveyana.Security.Nonce;

/// <summary>Where the exact AES key material came from, for forward-encryption policy.</summary>
internal enum AeadKeyOrigin
{
    FreshlyGenerated = 0,
    ImportedUnknownNonceHistory = 1,
}
