# SA-03 — Rollback authority contract (stage 1, 20 October 2026)

**English** | [Русский](Laveyana.Security.RollbackAuthorityContract.ru.md)

**Status: CONTRACT + UNIT FIXTURES ONLY. SA-03 OPEN. Phase 27 NO-GO. FileSystemKeyStore EXPERIMENTAL / TEST ONLY.**

## Threat and boundary

A valid, authenticated older `store.lsfs` can replace a newer snapshot without breaking the store's authenticated metadata. Per-key `KeyStoreRevision` does not protect deletion, name reuse prevention, or whole-store history against such replacement. The authority must anchor the **exact complete snapshot bytes** and a **global, monotonically increasing store sequence** to a domain which the snapshot attacker cannot roll back.

This stage adds contracts and a pure comparison gate under `Laveyana.Security.Abstractions.Rollback`, and NUnit contract tests. It does **not** modify `FileSystemKeyStore` I/O, existing on-disk schemas, APIs of `IKeyStore`, nonce allocation, or capability declarations. There is no production authority provider or integrated orchestration yet.

## Contract

- `RollbackCheckpoint`: pinned `StoreInstanceId` UUID, positive global `Sequence` and immutable 32-byte SHA-256 snapshot digest. Copies buffers defensively.
- `RollbackSnapshotDigest`: hashes the domain label `Laveyana.Security.RollbackSnapshot.SHA256.v1`, canonical `Guid.ToString("D")` bytes and exact persisted snapshot bytes. This **does not authenticate** a file. First validate the snapshot's authenticated contents and the pinned store UUID.
- `RollbackAuthorityState`: one committed checkpoint, optionally the *exact next* pending checkpoint. The pending state is durable and does not permit reads.
- `IKeyStoreRollbackAuthority`: `ReadAsync`, trusted one-time `TryEnrollAsync`, CAS `TryPrepareAsync` and CAS `TryFinalizeAsync`. Conforming providers must use durable, rollback-resistant, cross-process linearizable operations.
- `RollbackSnapshotGate.Inspect`: `CommittedMatch` only for an exact committed digest **with no pending intent**. `RequiresFinalization` is recovery-only, never permission to serve. Missing authority, older snapshot, conflicting state or unknown data yields `Rejected`.

## Proposed integration ordering (NOT implemented)

1. Pin the expected store UUID using trusted deployment configuration; authenticate the current whole snapshot.
2. Read external authority; require exact committed match and absence of a pending transition. If the authority record is missing, fail closed. Never silently register an existing store.
3. Generate the next full snapshot bytes. Durably CAS-prepare `(sequence + 1, digest)`; treat timeout/cancellation as **ambiguous**, not as an aborted prepare.
4. Under the existing exclusive cross-process store lock, replace and durably flush the exact bytes that were committed to by the digest. The filesystem durability guarantee still requires its own review.
5. CAS-finalize the pending checkpoint, and re-read/verify the authority and actual persisted bytes before exposing the new state. An ambiguous finalize must be reconciled from the authority.
6. Close/crash with a pending checkpoint: ordinary reads **fail closed**. A separately reviewed recovery process may finalize only after independently verifying that the durable, authenticated snapshot exactly matches the pending checkpoint. An older snapshot matching the previous committed checkpoint is **not** auto-accepted or auto-re-enrolled.

Because two separate resources are not an atomic transaction, safe availability following partial failure requires additional explicit recovery policy. This stage deliberately does not add a `CancelPrepare` or authority reset operation: resetting to an older checkpoint could enable rollback.

## Provider requirements and limits

- **Independence:** an ordinary file, encrypted file, local database, same-backup copy or process-local counter is NOT sufficient. An implementation also needs protected enrollment history, no delete-and-re-enroll attack, enforced linearization across processes, and crash/power-loss durability. No such provider has been selected or certified.
- **Provisioning:** enrolling a store must be an explicitly trusted first-time flow (sequence 1); missing authority during open is an error. Existing stores need deliberate migration with independent provenance, not automatic trust-on-first-use.
- **Concurrency:** a store-wide serialized writer protocol must ensure no writer commits or serves a newer state based on a stale authority observation. A mere CAS in the authority does not replace the filesystem lock.
- **Authentication/races:** digest equality alone is not an authentication result. Maintain authenticated snapshot validation, pinned store identity and file access confinement; coordinate the authority check with serving reads so an attacker cannot swap the file between checks.
- **SA-04 remains independent:** this contract does not establish durable AEAD nonce uniqueness or implement `IRollbackProtectedNonceAllocator`.

## Verification

`tests/Laveyana.Security.Tests/RollbackAuthorityContractTests.cs` covers validation, immutability, UUID/sequence binding, previous snapshot replay rejection, pending states, conflicting prepares and simulated ambiguous/crash windows. The test-only `VolatileProtocolFake` is **not** a candidate durable authority; these tests cannot prove platform rollback resistance.

Run on a machine with .NET SDK 10:

```powershell
 dotnet test tests/Laveyana.Security.Tests/Laveyana.Security.Tests.csproj -c Release --locked-mode --filter FullyQualifiedName~RollbackAuthorityContractTests
```

**This patch has not been compiled or run in the packaging environment.** Require Windows/Linux CI evidence on the exact revision, plus independent provider/recovery implementation and adversarial reviews, before considering SA-03 closed.
