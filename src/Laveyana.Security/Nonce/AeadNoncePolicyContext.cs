using Laveyana.Security.Abstractions.Identifiers;
using Laveyana.Security.Abstractions.Nonce;
using Laveyana.Security.Abstractions.Storage;

namespace Laveyana.Security.Nonce;

/// <summary>Trusted operation context; constructed at provider dispatch, not from user input.</summary>
internal sealed record AeadNoncePolicyContext(
    KeyReference Reference,
    AlgorithmId Algorithm,
    KeyStoreCapabilities StoreCapabilities,
    IRollbackProtectedNonceAllocator? Allocator,
    AeadKeyOrigin Origin = AeadKeyOrigin.PersistedUnknownNonceHistory,
    AeadRestoreState RestoreState = AeadRestoreState.Clean,
    AeadProviderNonceGuarantee ProviderGuarantee = AeadProviderNonceGuarantee.None,
    AeadNoncePolicyEngine.NonceBudget? RandomizedBudget = null);
