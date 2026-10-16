# Laveyana.Security — Architecture Decision Log

**English** | [Русский](Laveyana.Security.DecisionLog.ru.md)

> Scope: security-specific architectural tradeoffs, Generation 1. Entries inherited unchanged from the general Laveyana standards are omitted, preserving the original DXX IDs for traceability.

A new DXX is warranted only for a material security, compatibility, lifecycle, persistent-format or provider/storage architectural fork. Implementation-level choices do not require DXX. All listed decisions remain approved unless reopened for new technical evidence.

---

## D04. High-Level and Advanced stay in the same domain package

**Decision**

Keep safe High-Level APIs and explicit Advanced/interoperability APIs in the main Security domain until a future real boundary justifies another package.

**Rationale**

Avoids package fragmentation while keeping dangerous operations semantically explicit.

---

## D05. Logical and exact-version handles are separate

**Decision**

Logical handles bind ProviderId+KeyId and resolve current Active for forward use; exact handles bind ProviderId+KeyId+KeyVersion and never move automatically.

**Rationale**

Rotation cannot silently change historical identity semantics.

---

## D06. KeyVersion allocation is irreversible inside authoritative history

**Decision**

Discarded/deleted version numbers are not reused in represented authoritative history; gaps are valid.

**Rationale**

Persistent references remain unambiguous after failed/discarded version creation.

---

## D07. Discard ends in Deleted, not a fifth public state

**Decision**

Discarding Pending destroys never-activated material and produces public Deleted; an internal terminal reason may be retained for diagnostics.

**Rationale**

Keeps lifecycle compact without losing internal recovery/audit context.

---

## D08. KeyName uniqueness is provider-scoped

**Decision**

Generation 1 uniqueness is (ProviderId, KeyName) -> KeyId, not a global cross-provider namespace.

**Rationale**

Avoids hidden coordination between independent providers.

---

## D09. GetOrCreate requires store-level atomic name claim

**Decision**

Local keyed lock is only an optimization; correctness comes from atomic store claim/create of the unique name binding and aggregate.

**Rationale**

Prevents independent processes from creating two KeyIds for one provider/name.

---

## D10. ProviderId is persistent; ProviderAlias is runtime-only

**Decision**

Persistent references store stable ProviderId. Alias mapping is runtime configuration and duplicate ids/aliases are failures.

**Rationale**

Configuration refactoring cannot change stored cryptographic reference meaning.

---

## D11. Provider migration creates a new KeyId

**Decision**

Migration to another provider creates a new ProviderId/KeyId generation; existing KeyId is never moved and no redirect registry changes old references.

**Rationale**

Historical references stay immutable and source/destination can coexist.

---

## D12. Provider capabilities are granular

**Decision**

Do not require one giant backend interface; an operation requires both key policy permission and provider capability.

**Rationale**

Supports software, OS-backed, HSM, remote and non-exportable keys honestly.

---

## D13. IKeyStore belongs to Abstractions

**Decision**

IKeyStore is the public software-storage extension boundary; domain lifecycle logic remains in core Security.

**Rationale**

Custom stores do not need a dependency on concrete Security and cannot become the owner of lifecycle rules.

---

## D14. IKeyStoreProtector is defined before FileSystem

**Decision**

Protected FileSystem storage is built on an opaque protection contract from its first implementation; no temporary plaintext persistence path is allowed.

**Rationale**

At-rest security is architectural, not a future retrofit.

---

## D15. Default FileSystem is rollback-unprotected

**Decision**

Ordinary FileSystem declares ProvidesRollbackProtection=false unless an independent rollback-resistant authority is added.

**Rationale**

An old valid authenticated snapshot must not be mistaken for monotonic current state.

---

## D16. AEAD nonce strategy is capability-driven

**Decision**

Managed AES-GCM uses Randomized, RollbackProtectedDeterministic, or ProviderManaged. Deterministic allocation is forbidden on rollback-unprotected state.

**Rationale**

Nonce safety follows the declared threat model and is not delegated to ordinary consumers.

---

## D17. Imported AES material with unknown nonce history is restricted

**Decision**

Unknown prior nonce history blocks ordinary managed forward encryption unless an explicit safe provider/policy proves safe reuse.

**Rationale**

A new KeyId around identical raw material does not erase prior (key, nonce) use.

---

## D18. Managed crypto results record exact historical identity

**Decision**

EncryptedPayload, SignaturePayload, and MacResult record the exact KeyReference used by managed forward operations.

**Rationale**

Historical decrypt/verify stays deterministic after rotation.

---

## D19. Security-critical payload metadata is authenticated internally

**Decision**

Format, algorithm, exact key reference, critical flags and semantic parameters are cryptographically bound where applicable; application AAD is separate external context.

**Rationale**

Prevents metadata tampering without coupling Security to domain-specific meanings.

---

## D20. Sensitive material uses scoped access and leases

**Decision**

Opaque handles are default; raw material access uses callback scopes or disposable SensitiveMaterialLease with owned-buffer zeroization.

**Rationale**

Reduces accidental long-lived byte[]/string exposure while keeping interoperability possible.

---

## D21. Seal/Open is gated by standardized HPKE design

**Decision**

High-level asymmetric confidentiality is deferred until an analyzed standardized HPKE-compatible implementation strategy, vectors, limits, encoding and focused review are complete.

**Rationale**

Avoids inventing a custom hybrid cryptographic protocol merely to ship a feature.

---

## D22. Streaming AEAD requires a protocol gate

**Decision**

Encrypted streaming requires an analyzed segmented construction or a separately specified/reviewed protocol with position/stream binding, truncation/splice protection, limits and vectors.

**Rationale**

Makes framing and nonce semantics explicit and testable.

---

## D23. Generic defaults require a safe protector

**Decision**

AddSecurityDefaults() never guesses a platform protector and never falls back to plaintext; platform packages own platform-safe presets.

**Rationale**

Cross-platform defaults stay honest and fail fast when protection is missing.

---

## D24. Automatic rotation is explicit opt-in

**Decision**

Core contains rotation policy/engine but starts no hidden loop; optional hosted automation uses the same engine and Generic Host lifecycle.

**Rationale**

Keeps lifecycle ownership explicit and testable.

---

## D25. Persistent formats are versioned independently

**Decision**

Runtime models map to versioned persisted DTOs; metadata, protected envelope, encrypted payload, streaming format, and package version evolve independently.

**Rationale**

Enables controlled migrations and fail-closed handling of unknown newer formats.

---

## D27. Delete is not forensic secure erase

**Decision**

Normal delete means material is no longer accessible through the provider. Strong physical erase is advertised only by a backend that can guarantee it.

**Rationale**

Matches SSD/COW/snapshot/journal realities and avoids false security claims.

---

## D31. Re-protection is not cryptographic key rotation

**Decision**

Changing `IKeyStoreProtector` / at-rest envelopes preserves `KeyReference` and crypto material. The operation is an explicitly recoverable re-protection workflow; compromised material still requires actual key rotation.

**Rationale**

Separates two risk domains and avoids falsely claiming key rotation during storage re-encryption.

---

## D32. Known external restore requires reconciliation

**Decision**

A known restore of rollback-unprotected state blocks unsafe forward use until explicit reconciliation, typically preserving restored keys as historical-only and generating new KeyId/material for forward use. Authentication alone cannot detect an unknown older authentic snapshot.

**Rationale**

Prevents nonce, revision, and lifecycle state reuse after restore without claiming unavailable rollback detection.

---

## D33. Canonical stable identity encoding for Generation 1

**Decision**

Use nonempty lowercase UUID (`D`) text for stable ProviderId/KeyId/SecretId, positive invariant-decimal Int64 for KeyVersion, and fixed `provider/key/version` / `provider/secret` exact references. Application aliases are not part of persistent identity. Algorithm/capability IDs are stable lowercase tokens; CLR enum ordinal values must not be persisted. Naming restrictions and the complete grammar are specified in TechnicalSpecification §7.1.

**Rationale**

Changing runtime aliases, CLR names, locale, implementation versions or loading earlier snapshots must not reinterpret existing references. This only fixes identity encoding; versioned persistent envelopes and codecs remain future phases.

---

## D34. Policy-gated local primitives and history-only compatibility

**Decision**

Enforce purpose-specific algorithm classification within the Security domain. SHA-1/HMAC-SHA-1 are accessible only for explicitly requested `HistoricalVerification`. Unknown or unavailable algorithms never trigger fallback. New PBKDF2 derivations require a versioned Generation 1 work factor with at least 600,000 iterations; an explicitly named historical API handles older values. Safe-default and Advanced local RNG, HMAC and HKDF APIs apply distinct parameter requirements without pretending to be managed key services.

**Rationale**

Supports historical compatibility without weakening newly created values, while keeping future policy revisions independent of key lifecycle identity.

---

## D35. Sensitive array ownership and concurrent disposal

**Decision**

A sensitive lease offers `CreateCopy` (borrowed input, caller remains owner) and `TakeOwnership` (the existing array, no copy, explicit logical transfer). Read-only synchronous callbacks are the default. Active visitor scopes are not invalidated mid-call by concurrent disposal: disposal rejects new visitors and clears the owned array when the final active visitor exits. Built-in JSON serialization is explicitly rejected, and the lease never has a material-bearing `ToString`.

**Rationale**

Preserves well-defined zeroization ownership, avoids use-after-wipe within a callback, and prevents accidental material export through ordinary APIs. Existing caller aliases, deliberate copies and runtime/OS snapshots cannot be revoked by managed code.

---

## D36. Phase 5 capability resolution is metadata-only

**Decision**

Expose stable logical and exact handles separately; bind typed key views to an `IKeyMetadataResolver` returning fresh, immutable snapshots. Validate current Active on every forward metadata resolution; pin exact versions for historical checks. Reject inconsistent identity, lifecycle, kind or capability data. The result is a metadata preflight only; never treat it as authorization, a material lease, a nonce reservation or proof of provider/algorithm support. Actual providers must independently revalidate policy and capability at dispatch.

**Rationale**

Separates key discovery from provider security controls, prevents accidental cached-Active use and avoids TOCTOU authorization claims before backend contracts exist.

---

## D37. Pure lifecycle planning, tombstones and retention

**Decision**

Implement the Generation 1 state machine as **internal, pure, immutable** planning in core `Laveyana.Security`, not as a public provider/store contract. Every snapshot contains the persistent ProviderId/KeyId, logical state, monotonic version high-water mark, and represented version entries including Deleted tombstones. `CreatePendingVersion`, `Activate`, `Rotate`, `RetireKey`, `DiscardPending`, `DeleteVersion`, `ForceDeleteVersion`, `DeleteKey`, and `ForceDeleteKey` enforce the transition matrix and logical/physical Active invariant. Activate replaces two version states in one domain plan. Normal deletion requires explicit UTC time and satisfied per-version retention; force deletion is an explicitly dangerous bypass, but `ForceDeleteVersion` never removes current Active. CreatePendingVersion and Rotate are not idempotent; safe-looking no-ops do not authorize retry after ambiguous commits.

The authoritative backend in later phases must check revisions, enforce trusted retention metadata, persist state and material side effects atomically, protect the high-water mark from ordinary restore/rollback as far as supported, and release a claimed key name only after committed deletion. A pure plan **is not a transaction, durable action or authorization**. Compaction is allowed only if high-water information survives; rollback-unprotected older snapshots cannot guarantee global non-reuse.

**Rationale**

Keeps security-critical lifecycle invariants testable without I/O, separates provider-specific durable operations from policy, and avoids prematurely exposing unstable lifecycle internals as third-party extension API.

---

## D38. Immutable provider registry and metadata-only backend discovery

**Decision**

Place `IKeyProviderBackend` and immutable provider capability declarations in Abstractions, independent of concrete Security and `IKeyStore`. The Phase 7 interface provides identity/metadata/capability discovery, not cryptographic dispatch. The immutable composition registry rejects duplicate ProviderId/ProviderAlias and mutable backend identities. Exact routing always uses persisted ProviderId, never probes alternative backends and validates response identity. Provider capability advertisements and metadata preflight are not authorization grants.

**Rationale**

Permits independent OS/HSM/remote adapters without expanding dependency chains, preserves existing KeyReference semantics, rejects misrouting rather than concealing it, and leaves atomic security checks at operation execution in later phases.

---

## D39. Atomic aggregate storage and independent protector/nonce extension contracts

**Decision**

Place all three Phase 8 extension boundaries exclusively in Abstractions. An `IKeyStore` must use a single durable transaction/linearization point for name claim and aggregate creation, versioned protected material changes with metadata CAS, and aggregate deletion with material cascade and name release. Revisions begin at 1, advance one per successful replacement and cannot wrap within the authoritative history; deleted KeyIds remain reserved. A definite rejection has no effects, but cancellation or exceptions near commit require reconciliation. Material reads validate expected revision. Protected bytes are never taken for plaintext, and creation of an envelope does not authenticate it.

`IKeyStoreProtector` authenticates identity, purpose and versioned AAD with a stable `ProtectorReference`, internally owning unexportable root material. `IRollbackProtectedNonceAllocator` is independent and optional, with strong external-restore-resistant reservation guarantees; no default filesystem counter is accepted as an implementation.

**Rationale**

Ensures multi-process name uniqueness, closes metadata/material partial-update windows, prevents mistaken rollback/nonce guarantees and preserves independent third-party store/protector extensibility without weakening security defaults.

---

## D40. Store-backed software lifecycle with fail-closed commit semantics

**Decision**

Use the Phase 6 internal state machine as the only authority for software lifecycle transitions, and the Phase 8 store as the only authority for material/state commits, unique name claims and name release. `SoftwareKeyProviderBackend` creates only generated symmetric key material and binds metadata to the exact next revision (1 for create, `expected+1` for replace). Definite CAS conflicts abort, without automatic retries. A thrown mutating store operation is reported as an unknown commit; the caller must reconcile before another request. `GetOrCreate` resolves definitive name conflicts only after verifying identity, algorithm, capabilities and retention. Keep an immutable protected, bounded provisional `LSM1` state format until the migration phase. Do not announce executable provider crypto capabilities before operation dispatch exists.

**Rationale**

Prevents split-brain name creation, loss of rotation history, material/metadata divergence, unsafe repeated allocation after ambiguous commits, and misleading capability declarations. Durable multi-process safety and rollback prevention still depend on implementations of the external contracts and are not claimed by this phase.

---

## D41. Internal AEAD nonce issuance bound to exact key generations

**Decision**

Introduce an internal AES-256-GCM nonce policy engine selecting ProviderManaged only with a verified backend guarantee; RollbackProtectedDeterministic only with *both* an independent rollback-resistant allocator and store rollback protection; otherwise Randomized CSPRNG for freshly generated material. Deterministic sessions burn unused committed 64-counter ranges and fail closed on ambiguous reservations. Randomized issuance has a process-only 2²⁰ exact-key counter; cumulative key lifetime limits must be implemented later. Known restore invalidates the old generation until reconciliation/re-key with a new KeyId, and imports with unknown nonce history cannot perform ordinary managed encryption. The engine does not execute AES and cannot authorize operations.

**Rationale**

Separates local issuance from verified durable state and future encryption dispatch. Avoids presenting process-local budgets as distributed rollback resistance and prevents a silent fallback after nonce authority errors.

---

## D42. Canonical metadata generations and explicit migration

**Decision**

New software metadata uses `LSMD` v2 with CLR-independent wire tokens and deterministic serialization. Legacy `LSM1` is accepted only after authenticated reading. Migration produces bytes in memory; persistence requires an explicit CAS plus re-protection under the new revision. `LSPB` bootstrap and `LSNC` nonce checkpoint are versioned wire contracts, not proofs of identity, authenticity or rollback resistance. Unknown versions and malformed records fail closed.

**Rationale**

This decouples durability from runtime enums, preserves key history/high-water and prevents an implicit downgrade of protector or nonce authority after restoring a snapshot. Concrete durability and crash recovery remain provider responsibilities.

---

## Decision log maintenance

**Phase 26 numbering verification (2026-10-10):** There are **50 security-specific decision entries** with IDs D04–D57. The intentional gaps D01–D03, D26 and D28–D30 duplicate shared ecosystem rules already incorporated into the self-contained master prompt; they are **not missing security decisions** and must not be invented or renumbered. EN/RU entry ID sets match. D57 is the most recent decision; document synchronization alone does not require a D58. These records describe decisions, **not successful security acceptance**; the Phase 27 audit remains open.
## D43. Single authenticated filesystem snapshot behind an explicit security gate

**Decision**

Phase 12 uses one versioned `LSFS/LSFB` snapshot, a SHA-256 manifest authenticated by an externally supplied `IKeyStoreProtector`, an exclusive interprocess lock, and atomic file replacement. Durable tombstones reserve former KeyIds within the available history. No root secret is stored in the bootstrap and there is no plaintext fallback. Writes require explicit `EnableExperimentalWrites` and remain non-production until Phase 13. `ProvidesRollbackProtection=false`; external restore detection and directory-entry fsync are not claimed.

**Rationale**

One snapshot places names, CAS, protected metadata/material and used IDs at a single replacement point. External protector authentication validates routing integrity without a filesystem root key. The release gate makes unimplemented platform hardening and independent rollback authority explicit.

## D44. Platform filesystem checks with retained experimental release gate

**Decision**

Linux opens a vetted private `0700` directory by descriptor, performs no-follow directory-relative child I/O with strict `statx` owner/type/mode checks, uses `flock`, and fsyncs the directory after atomic rename. Unsafe pre-existing roots, parent directory permissions, symlinks and foreign-owned files are rejected without hidden chmod/ACL repair. Windows creates an isolated ACL and checks owner, DACL, ancestors and reparse points. Unsupported hosts fail closed.

**Limitations and rationale**

Windows mutations remain path-based and are not certified against hostile race attacks; Linux and Windows require actual .NET/platform test execution. This change intentionally **does not** enable production writes, add a protector or declare rollback protection. `EnableExperimentalWrites` continues to mean test use only. This prevents conflating platform preflight checks with verified operational security.


## D45. Windows DPAPI CurrentUser — explicit platform protector, no fallback

**Decision.** The `IKeyStoreProtector` implementation in `Laveyana.Security.Windows` uses DPAPI CurrentUser (not LocalMachine): `LSWP` v1, domain binding of `ProtectorReference`/purpose/AAD, strict version validation and an inner plaintext checksum. Windows owns the root key. Applications supply a stable generation, which cannot be changed without migration. Native plaintext is wiped. Unsupported OSes fail closed, with no plaintext fallback or assembly scanning.

**Limitations.** DPAPI does not isolate same-user processes, prevent rollback, or provide a universal cross-platform default. FileSystem TOCTOU and real .NET/Windows acceptance tests remain open. Phase 14A owns re-protection.


## D46. Re-protection is an explicit full-aggregate CAS, not key rotation

**Decision.** Read past `ProtectorReference` generations only via an explicitly
registered, bounded, immutable exact-reference router. A current protector is the only
writer. For one key, authenticate metadata and all non-deleted material before atomically
replacing metadata (next-revision AAD) and all historical material in a single CAS.
Reject unknown and compromised generations; on compromise do not claim key confidentiality
is restored by re-wrapping. No automatic fallback, partial migration or retry of ambiguous
commits. Max 128 live versions per atomic migration; oversized aggregates require a
separate future design, not a partial update.

**Tradeoffs/limits.** Read-only legacy protectors must remain available through the
migration/backup transition. The status is configuration, not a durable revocation registry.
`AlreadyCurrent` is an authenticated observation but not a globally linearizable read.
DPAPI reference changes do not necessarily rotate its OS root. Failure injection tests are
written but actual .NET build, NUnit, Windows DPAPI and platform hardening gates remain open.

**FileSystem-specific extension.** The independently authenticated outer snapshot
must be migrated explicitly before inner key records. `OpenForMigrationAsync` requires
pinned store UUID, exact legacy reference and experimental writes. Two atomic file
replacements (snapshot then bootstrap) are not a combined atomic transaction; recover
mixed state by re-opening and re-authenticating with the trusted old/current reader,
then repeating the idempotent root migration. Normal opens fail closed until bootstrap
and snapshot are current. Application writes remain blocked in an unfinished migration
session. This mechanism does not address valid-snapshot rollback or Windows TOCTOU.

**Additional Phase 14A defense:** newly protected envelopes and the outer snapshot are decrypted and compared against their input **before** any commit attempt. This does not replace independent protector validation, review and real .NET/Windows/Linux testing.

## D47. Exact-reference managed result framing and AEAD metadata binding

**Decision.** Separate immutable managed values and four versioned canonical codecs (`LEP1`, `LDP1`, `LSP1`, `LMR1`) are housed in Abstractions, independently of providers. Public byte arrays are copied in/out, unknown versions/flags/algorithms fail closed, and detached ciphertext length remains explicit. AEAD authenticates a versioned, domain-separated internal context composed of exact KeyReference, algorithm, nonce, tag/ciphertext sizes and separately supplied external application AAD. The external AAD is not stored in the payload. Constructor and codec do **not** claim to verify authenticity.

**Rationale / limitations.** A logical key may rotate, but its produced ciphertext must permanently identify the exact used key version. Delimiter-free or ad hoc AAD would allow ambiguous reinterpretation of cryptographic fields. Actual tag verification, provider authorization, exact Active resolution, nonce policy and signed/MAC results remain future phases. Until .NET 10 build and test execution, formats are provisional and must not be shipped as a stable production interoperability contract.


## D48. Provider-owned AEAD execution; exact Active selection and tag-only TryDecrypt

**Decision.** Implement bounded whole-buffer AES-256-GCM in `SoftwareKeyProviderBackend`, expose optional `IAuthenticatedEncryptionBackend` in Abstractions and strict `ProviderRegistry.RouteAead` routing by persisted ProviderId. After an authenticated metadata read, select the current Active exact version and fetch its protected material at the same durable aggregate revision. Only that version can encrypt; decrypt uses the exact Active/Retired reference embedded in the payload. Reuse the Phase 15 canonical internal/external AAD and Phase 10 nonce policy. No caller-defined nonce, implicit algorithm downgrade, material export, or unverified provider-managed fallback.

**Failures and limits.** `TryDecrypt` catches only AEAD `AuthenticationTagMismatchException`; material/store/protector, policy, cancellation and format errors remain exceptional. Partial plaintext is wiped on failure, and temporary encrypt plaintext is wiped. Limit messages to 16 MiB (matching payload serialization) and external AAD to 64 KiB. AES-GCM is the only executable algorithm this phase; ChaCha20-Poly1305 execution is deferred pending a separately audited nonce policy. Randomized nonce usage is bounded only per-process and cannot by itself guarantee uniqueness over restarts/multiple processes. The optional allocator requires separately verified rollback resistance; existing file stores and Windows paths do not meet the production gate. Unit/integration scenarios are written but no .NET build/test execution is claimed.

## D49. MAC operations in the protected software store; signatures through an independent versioned execution boundary

**Decision.** The existing symmetric `SoftwareKeyProviderBackend` executes HMAC-SHA-256/384/512 without exposing raw secret bytes. MAC creation selects the current Active version, while verification pins an exact Active/Retired version; full tags are compared in fixed time. Separate `Mac` and `VerifyMac` capabilities are required. The optional `IManagedMacBackend` lives in Abstractions, and provider routing uses the persistent ProviderId.

**Asymmetric boundary.** `IManagedSignatureBackend` and `IVersionedSignatureKeyOperations` allow a trusted provider-owned signing service to perform ECDSA P-256 SHA-256 or RSA-PSS SHA-256 without changing the symmetric key store schema. The adapter checks advertised capabilities, fresh metadata, exact state, key kind and algorithm policy; the executor MUST independently enforce authorization and revocation at execution. The concrete `EphemeralSignatureKeyOperations` supports actual .NET signatures with transferred private key objects but is strictly process-local and NOT a durable backend.

**Failure semantics and unresolved gates.** Invalid MAC/signature returns false; unavailable, unauthorized, deleted, wrong-algorithm, broken-provider or cancelled operations throw. Historical data never silently falls back to a newer version. Missing production-grade persistent asymmetric key management, cross-process revocation, .NET 10 build/NUnit evidence, FileSystem rollback/Windows TOCTOU hardening keep the security and release gates open. Phase 18 may build derivation/agreement independently.

## D50. Mandatory P-256 ECDH KDF and explicit ephemeral derived material

**Decision.** Select current Active exact P-256 private key after metadata/provider capability checks; the trusted executor independently rechecks revocation and access when it performs ECDH. Raw shared secret stays internal and is erased after mandatory HKDF-SHA-256. Domain-separated v1 info incorporates purpose, application context, output length and both sorted canonical public SPKIs; `salt=SHA256(info)`. Protected software HKDF derives only from an Active version read at the expected store revision and binds info to an exact `KeyReference`. No algorithm fallback, persistent default material export or KDF bypass.

**Tradeoffs.** `DerivedKeyLease` wipes an exclusively owned derived buffer on disposal and supplies only a borrowed synchronous visitor. Explicit export requires external `IDerivedMaterialExportPolicy` and caller-owned copy hygiene. The concrete ECDH executor is process-only and does not authenticate peers, implement cross-process revocation or persistent private key storage. Independent cryptographic vectors are generated; actual .NET build and NUnit, FileSystem rollback and Windows TOCTOU security gates remain open. PQC KEM is not a Generation 1 default.


## D51. Phase 19 HPKE implementation remains deferred pending runnable conformance and trusted key execution

**Decision.** Begin with an exact RFC 9180 Appendix A.3.1 Base-mode P-256/HKDF-SHA256/AES-128-GCM interoperability reference (not a modification of the default managed AES-256-GCM API). Independently validate the public vector through a test-only Python implementation. Do not derive an HPKE protocol from existing Phase 18 derivation or expose `Seal`, `Open`, `SealedPayload`, provider capabilities or a stable serialized envelope until production suite selection, reviewed implementation/provider, C# conformance and independent interoperability, exact-key access/revocation, header/info/AAD binding and focused security review all pass.

**Status/limitations.** Reference evidence succeeds (six published ciphertext sequences and 14 negative checks), but .NET SDK/NUnit, production asymmetric key custody, interoperability and security review are **unverified**. HPKE is intentionally UNSUPPORTED/DEFERRED under D21 and Roadmap release-optional scope. See `Laveyana.Security.HpkeGate.md`.

## D52. Streaming SHA/HMAC may ship separately; segmented AEAD remains gated

**Decision.** Provide SHA-2 and provider-owned, full-length HMAC streaming with a bounded one-pass reader, explicit byte limit, optional trusted expected length, no stream ownership, exact version and end-of-operation revision recheck. MAC verification returns `false` only for mismatched tags, not for incomplete input or provider failure. The external `IStreamingMacBackend` is optional and exact-routed. No authenticated-encryption streaming API is published without a separate reviewed segmented AEAD format, authenticated finalization and conformance/security tests.

**Limitations.** Untrusted expected length alone does not prevent truncation; an immutable input or snapshot is the caller's responsibility. .NET build, NUnit and platform security review remain open. See `Laveyana.Security.StreamingGate.md`.


## D53. Secrets stay read-only by default with exact-ID routing and owned scoped reads

**Decision.** The base `ISecretProvider` has only `FindAsync` and `GetAsync`. Secret identities are `(ProviderId, SecretId)` without universal versioning. `SecretReadResult` owns a zeroizing lease; `SecretHandle` exposes callback-scoped reads and rejects mismatched identities. An immutable, separate `SecretProviderRegistry` routes only by stable ID. Aliases are runtime-only. `ISecretManagementProvider` is optional, requested explicitly. Advertised open/export capabilities are separate, default false, and do not authorize a read.

**Rationale.** Avoid duplicating key rotation semantics, broadening a read-only provider into a manager, retaining implicit plaintext copies, or selecting the wrong provider after an alias change. Keep actual authorization and access enforcement in the provider at each operation.

**Limitations.** Borrowed spans do not prevent deliberate copies. Cancellation cannot preempt a synchronous callback. No built-in persistent secret provider, process-wide revocation guarantee, automatic write or .NET/NUnit execution in this stage.



## D54. DI assembles an immutable snapshot without owning cryptographic policy

**Decision.** `AddSecurity` and `AddSecurityDefaults` create a bounded,
explicit `SecurityCompositionSnapshot` in the dedicated DI assembly. Structural
configuration errors fail during registration/resolution, while required provider-wide
capabilities are verified by a startup-only `IHostedService` or an explicit call in
non-host consumers. Registries route by exact stable `ProviderId`, never by aliases.
Configured external component types must already have singleton registrations. Conflicting
key/secret aliases are rejected within a composition.

**Rationale/tradeoffs.** Synchronous DI must not block async FileSystem initialization:
applications explicitly open the store before composition. No startup scanning, implicit
protector choice, plaintext fallback, worker, or file bootstrap is introduced.
`AddSecurityDefaults` without a protector fails. Dynamic capabilities and permissions
must be rechecked when an operation is performed; configured requirements are only
startup assertions. Non-host consumers must explicitly invoke async capability validation.

**Open gates.** Windows convenience preset, actual .NET build/NUnit/host integration tests,
plus all preexisting platform and FileSystem production security gates.


## D55. Version-fenced opt-in rotation with authoritative external scheduling

**Decision.** Manual and due rotation use one `RotationEngine` and the optional
`IConditionalKeyRotationBackend` contract, enforcing a caller-supplied expected
Active version within the backend's CAS transaction. The policy uses `TimeProvider`
and a trusted application-owned UTC activation anchor. The hosted worker is never
registered by defaults: it requires explicit DI opt-in and a durable one-shot
`IRotationWorkSource` whose atomic claim is persisted before execution. Failures,
including an unknown commit result, are not blindly retried.

**Tradeoffs / open gates.** A durable schedule backend and operational reconciliation
are application responsibilities. A crash after claim may leave a blocked rotation;
this is safer than repeating a possibly successful non-idempotent rotation. The
in-process worker cannot guarantee safety if its source breaks the durable-claim
contract. Authorization and safety of historical-key deletion are separate. .NET
compilation, NUnit, and real cross-process execution remain unverified.


## D56. Explicit checkpointed migration without key reference redirection

**Decision.** Migration uses distinct immutable ProviderId/KeyId identities,
exact Active source version snapshots and the staged `ProviderMigrationOrchestrator`.
The software destination regenerates unrelated material; native secure transfer
requires explicit source/destination contracts and provider-enforced trust and
transport policy. There is no raw export in this API. Preparation and target
validation do not constitute application cutover. A matching application receipt
asserts independently durable data/reference migration; old `KeyReference` values
are never redirected. Source retirement/deletion is optional and requires a
separate provider-enforced lifecycle contract, never force deletion.

**Gates / tradeoffs.** Checkpoint authorization, persistence, CAS sequencing and
reconciliation of unknown commit outcomes belong to the application. Native
provider implementations and durable recovery are not bundled. Compiler/NUnit,
security review and existing platform/rollback gates remain open.

## D57. Opt-in observability with bounded event codes and optional audit sink

**Decision.** `SecurityObservability` in the core assembly uses standard
`ILogger<SecurityObservability>`, `ActivitySource`, and `System.Diagnostics.Metrics`.
Only fixed `SecurityOperation` and `SecurityOperationOutcome` values are exposed.
Logs include `{Operation}` / `{Outcome}`; spans and operation metrics have only
`security.operation` and `security.outcome` tags, with duration measured in milliseconds.
ProviderId/KeyId/SecretId, names, versions, AAD, secret lengths, exception messages,
payload, plaintext, and ciphertext are never emitted. Outcomes are classified without
serializing exceptions. A false MAC result or null TryDecrypt result is `Negative`,
whereas operational failure cannot be recast as a verification negative.

**Composition.** Observability is explicitly passed to `SoftwareKeyProviderBackend`,
`ProviderRegistry`, and `SecretProviderRegistry`, or selected through DI
`WithObservability`. Manual composition remains available; exporters are selected
by the application. Activity trace IDs are not used as metric labels. Operations
performed directly through unrelated custom providers are not automatically observed:
those providers must instrument their own operation boundaries.

**Audit.** `ISecurityAuditSink` receives a bounded `SecurityAuditEvent` with the
operation, outcome, UTC timestamp, and optional trace ID. This is a best-effort
notification, **not** a compliant or durable audit trail: no storage, delivery guarantee,
idempotency guarantee, or atomic coupling to a commit is provided. Logging or sink
failures cannot change an already committed cryptographic operation; audit delivery
failures are counted separately. Applications own durable auditing, service levels,
and access controls; sinks must avoid blocking security operations.

**Open gates.** Tests cover sensitive-data leakage, bounded dimensions, Activity
correlation, real AES-GCM outcomes, and broken sinks. Real .NET 10 compilation,
NUnit execution, and Windows/Linux security testing are not yet confirmed; Phase 25
and the overall production gate remain open.

