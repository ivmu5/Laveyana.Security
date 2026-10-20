# SA-03 — Rollback authority contracts (stages 1 and 2A, 20 October 2026)

**English** | [Русский](Laveyana.Security.RollbackAuthorityContract.ru.md)

**Status: CONTRACTS + UNIT FIXTURES ONLY (Stage 2A request resolution; no FileSystem integration). SA-03 OPEN. Phase 27 NO-GO. FileSystemKeyStore EXPERIMENTAL / TEST ONLY.**

## Threat and boundary

A valid, authenticated older `store.lsfs` can replace a newer snapshot without breaking the store's authenticated metadata. Per-key `KeyStoreRevision` does not protect deletion, name reuse prevention, or whole-store history against such replacement. The authority must anchor the **exact complete snapshot bytes** and a **global, monotonically increasing store sequence** to a domain which the snapshot attacker cannot roll back.

Stage 1 adds contracts and a pure comparison gate under `Laveyana.Security.Abstractions.Rollback`, and NUnit contract tests. It does **not** modify `FileSystemKeyStore` I/O, existing on-disk schemas, APIs of `IKeyStore`, nonce allocation, or capability declarations. There is no production authority provider or integrated orchestration yet.

## Contract

- `RollbackCheckpoint`: pinned `StoreInstanceId` UUID, positive global `Sequence` and immutable 32-byte SHA-256 snapshot digest. Copies buffers defensively.
- `RollbackSnapshotDigest`: hashes the domain label `Laveyana.Security.RollbackSnapshot.SHA256.v1`, canonical `Guid.ToString("D")` bytes and exact persisted snapshot bytes. This **does not authenticate** a file. First validate the snapshot's authenticated contents and the pinned store UUID.
- `RollbackAuthorityState`: one committed checkpoint, optionally the *exact next* pending checkpoint. The pending state is durable and does not permit reads.
- `IKeyStoreRollbackAuthority`: `ReadAsync`, trusted one-time `TryEnrollAsync`, CAS `TryPrepareAsync` and CAS `TryFinalizeAsync`. Conforming providers must use durable, rollback-resistant, cross-process linearizable operations.
- `RollbackSnapshotGate.Inspect`: `CommittedMatch` only for an exact committed digest **with no pending intent**. `RequiresFinalization` is recovery-only, never permission to serve. Missing authority, older snapshot, conflicting state or unknown data yields `Rejected`.

## Stage 2A — request identity and lost-response resolution (CONTRACT ONLY)

The original `IKeyStoreRollbackAuthority` remains source-compatible. The optional
`IKeyStoreRollbackRequestAuthority` derives from it and adds **request-aware overloads**
of trusted enrollment, preparation and finalization, plus `ResolveAsync(store UUID, request ID)`.
`RollbackRequestId` is a nonempty immutable GUID value object: the caller generates a fresh
random ID for one semantic RPC and **durably stores that ID, the operation kind, exact
checkpoints and recovery candidate before it can transmit the request**. A retry of the
same RPC reuses its ID and identical arguments. The authority must durably bind that tuple
to a single decision and reject mismatched reuse without mutating state.

`RollbackRequestResolution` has three possible outcomes:

| Outcome | Meaning / caller rule |
| --- | --- |
| `Applied` | This exact request was durably applied, even if the store state has since advanced. Reconcile the corresponding original transition; never create a new semantic mutation as a retry. |
| `NotApplied` | This exact request did not apply **and is permanently fenced** against late delivery/retry. Only this terminal decision permits retiring the request intent after checking other store preconditions. |
| `Unresolved` | The request may still execute later. Preserve its candidate/intent and **fail closed**. A successful ordinary `ReadAsync` of the old committed checkpoint does not settle this question. |

`ResolveAsync` MUST NOT turn "request not found" into `NotApplied` unless it durably
creates an independent fence/tombstone that future delayed deliveries cannot bypass.
Providers unable to fence must return `Unresolved` or fail. All decisions and fences
must survive crashes, service backup rollback, failover and transport retries under the
selected trust model, with no unsafe TTL expiration. A returned `false` from a request-aware
mutation is a durable terminal no-effect decision for that ID. After timeouts/exceptions,
callers do not infer such a decision; they resolve the ID explicitly. A UUID mismatch is
an error, not proof of non-execution. No two different argument tuples may share an ID.

**Security boundary:** protected-mode clients MUST exclusively use the request-aware
mutation overloads. A conforming provider MUST disable or prevent inherited untracked
mutations from bypassing its request decision/fencing records for protected stores.
The existence of this optional interface does NOT attest to a provider's independence,
rollback resistance or durable fencing; integration must verify those properties.

**Not delivered in Stage 2A:** external service, HTTP, database, root-file staging,
commit/recovery state machine, FileSystem wiring, provisioning, power-loss guarantees,
nonce allocation and `ProvidesRollbackProtection=true`. The test fake is volatile and
only demonstrates the required control-flow semantics.

## Proposed integration ordering (NOT implemented)

1. Pin the expected store UUID using trusted deployment configuration; authenticate the current whole snapshot.
2. Read external authority; require exact committed match and absence of a pending transition. If the authority record is missing, fail closed. Never silently register an existing store.
3. Generate the next full snapshot bytes, durably stage the exact candidate and request identity/arguments **before contacting the authority**. Durably CAS-prepare `(sequence + 1, digest)`; treat timeout/cancellation as **ambiguous**, not as an aborted prepare. Resolve the exact request or remain fail-closed; an ordinary state read cannot fence a late RPC.
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

`tests/Laveyana.Security.Tests/RollbackRequestAuthorityContractTests.cs` covers request IDs,
late prepare/enroll after a resolution fence, genuinely unresolved requests, lost prepare
and finalize replies, terminal conflicts, immutable argument bindings and blocked legacy
mutation entry points (in the fake). This is **not** a durable authority conformance test;
real provider tests must include restarts, durable tombstones, delayed/duplicated RPCs,
failover and restored server backups.

Run on a machine with .NET SDK 10:

```powershell
 dotnet test tests/Laveyana.Security.Tests/Laveyana.Security.Tests.csproj -c Release --locked-mode --filter "FullyQualifiedName~RollbackAuthorityContractTests|FullyQualifiedName~RollbackRequestAuthorityContractTests"
```

**This patch has not been compiled or run in the packaging environment.** Require Windows/Linux CI evidence on the exact revision, plus independent provider/recovery implementation and adversarial reviews, before considering SA-03 closed.

### Stage 2B1: read-only file inspection (experimental)

`FileSystemKeyStoreOptions.RollbackAuthority` opts into a **read-only inspection probe**, not a protected storage profile. Opening requires `ExpectedStoreInstanceId` and `EnableExperimentalWrites=false`. Every authenticated `LoadAsync` compares the **same original persisted bytes** with a fresh authority observation under the store lock; only `CommittedMatch` permits returning records. Missing authority, pending intent, foreign UUID, replayed snapshot and authority I/O errors fail closed. This option provides no auto enrollment, prepare, publication, finalize or recovery.

**No downgrade guarantee:** a caller can still omit the option or use an old binary to open the existing v1 snapshot. `ProvidesRollbackProtection` remains `false`, even with the option supplied. This temporary capability is strictly for testing Stage 1 gates against real authenticated filesystem snapshots. Stage 2B protected writes require new outer format/profile pin, durable candidate + intent, request-fenced CAS, recovery and verified filesystem barriers. Do not use with production secrets.
