using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Storage;

/// <summary>Durable, replaceable software-key persistence and consistency boundary.</summary>
/// <remarks>
/// All implementations MUST atomically claim provider-scoped names with aggregate creation;
/// CAS-replace metadata and material upserts/deletes as one durable transition; and delete
/// metadata, every material version and the name binding as one durable transition.
/// A rejected conditional write MUST have no effects. Create commits revision 1. Every successful replace commits exactly expected revision + 1;
/// the store MUST reject exhausted revisions and MUST NOT reuse a KeyId. These exact
/// revision steps are required to pre-authenticate the next metadata envelope. Reads of material
/// MUST check the requested aggregate revision atomically with the read. Stores do not decide
/// lifecycle validity, decrypt envelopes or expose plaintext material. A provider can implement
/// this interface using Abstractions alone; filesystem and custom stores must provide their
/// own cross-process coordination, crash recovery and protection-at-rest implementation.
/// If an exception, crash or cancellation occurs around commit, the caller MUST reconcile
/// committed state before retrying a non-idempotent operation. No rollback is implied.
/// </remarks>
public interface IKeyStore
{
    /// <summary>Gets explicitly declared rollback characteristics; defaults must not claim protection.</summary>
    KeyStoreCapabilities Capabilities { get; }

    /// <summary>Finds a committed aggregate by exact provider-scoped name, or returns null.</summary>
    ValueTask<KeyStoreEntry?> FindByNameAsync(ProviderId providerId, KeyName name,
        CancellationToken cancellationToken = default);

    /// <summary>Finds a committed aggregate by stable provider and generation ID, or returns null.</summary>
    ValueTask<KeyStoreEntry?> FindByIdAsync(ProviderId providerId, KeyId keyId,
        CancellationToken cancellationToken = default);

    /// <summary>Reads material only if the committed aggregate still has the expected revision.</summary>
    ValueTask<KeyStoreMaterialReadResult> ReadMaterialAsync(KeyReference reference,
        KeyStoreRevision expectedRevision, CancellationToken cancellationToken = default);

    /// <summary>Atomically creates a protected aggregate, unique name binding and initial materials.</summary>
    /// <remarks>A taken name or reused KeyId is a definitive conflict, not a successful GetOrCreate.</remarks>
    ValueTask<KeyStoreMutationResult> TryCreateAsync(KeyStoreCreateRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>CAS-updates protected metadata and material changes at one durable linearization point.</summary>
    ValueTask<KeyStoreMutationResult> TryReplaceAsync(KeyStoreReplaceRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Conditionally removes the entire generation, all material and its name binding.</summary>
    /// <remarks>Lifecycle and retention checks belong to orchestration, not to this store.</remarks>
    ValueTask<KeyStoreMutationResult> TryDeleteAsync(ProviderId providerId, KeyId keyId,
        KeyStoreRevision expectedRevision, CancellationToken cancellationToken = default);
}
