using Laveyana.Security.Abstractions.Identifiers;

namespace Laveyana.Security.Abstractions.Nonce;

/// <summary>OPTIONAL independent rollback-resistant, atomic deterministic AEAD nonce allocator.</summary>
/// <remarks>
/// Do not implement this interface over ordinary rollback-unprotected filesystem counters.
/// A conforming authority atomically reserves globally nonoverlapping ranges per exact
/// key generation, preserves prefix uniqueness across counter-state reinitialization,
/// rejects exhaustion, prevents reuse after crash, process restart and external restore,
/// and never returns a range before its reservation is durable. Unused committed ranges
/// are permanently burned. Exceptions and cancellation around commit may be ambiguous;
/// callers MUST reconcile or abandon the uncertain reservation, never assume reuse is safe.
/// Availability of this interface is not proof of an implementation's rollback resistance;
/// deployments must establish that capability independently.
/// The bundled software AES-GCM backend currently rejects supplied deterministic allocators
/// because no independently verified allocator/profile integration is enabled.
/// </remarks>
public interface IRollbackProtectedNonceAllocator
{
    /// <summary>Durably reserves a range or throws on unsupported state or exhaustion.</summary>
    ValueTask<NonceRangeReservation> ReserveAsync(KeyReference reference, uint count,
        CancellationToken cancellationToken = default);
}
