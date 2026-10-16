# Laveyana.Security — Roadmap

**English** | [Русский](Laveyana.Security.Roadmap.ru.md)

> Generation 1 implementation plan. A phase closes only after its acceptance criteria and relevant tests succeed; never proceed through a known violated security invariant. HPKE and encrypted AEAD streaming may remain deferred after their independent security gates.

Each phase explicitly records purpose, changes, dependencies, acceptance criteria, verification and limitations. Implementation details can be chosen within an approved phase; significant architectural conflicts follow the Decision Log.

---


> **H01 infrastructure phase: CLOSED (2026-10-16).** Verified Release/NUnit on both OSes, protected `master`, and first successful manual monthly-regression run. [Closure evidence](../hardening/H01-Setup.md). This checkpoint does not close Phase 27 security findings or permit production use of the experimental filesystem store.

> **Current verification status (2026-10-16):** H01 `Verify` passed Release builds and NUnit on both Windows and Ubuntu, plus source/docs checks. Earlier functional phases are not thereby production-accepted: Windows TOCTOU, rollback and nonce lifetime gates remain open. Historical “not yet tested” remarks refer to the phase at the time. See [README](../../README.md) and [security review](../audit/Laveyana.Security.Phase27.SecurityAudit.md).

## Phase 1 — Repository foundation

- **Purpose:** Create the repository, projects, build policy, and documentation baseline.
- **Changes:** Create Abstractions, Security, FileSystem, DependencyInjection, Tests, IntegrationTests; configure net10.0, nullable, analyzers, XML docs, .editorconfig, Central Package Management, shared release version, current EN/RU design baseline without README/CHANGELOG/LICENSE placeholders.
- **Dependencies:** None.
- **Acceptance criteria:** Clean build; no cycles; all identities use Laveyana.*; file-scoped namespace and English-only source documentation enforcement are active.
- **Tests / manual checks:** Build all projects; inspect analyzer/XML-doc output; scan .cs files for Russian comments.
- **Remaining limitations:** No domain implementation yet.

---

## Phase 2 — Stable identifiers and domain model

- **Purpose:** Freeze stable value semantics before workflows depend on them.
- **Changes:** Implement ProviderId/Alias, KeyName/Id/Version/Reference, SecretId/Reference, descriptors, states, capability IDs, algorithm IDs, validation.
- **Dependencies:** Phase 1.
- **Acceptance criteria:** Immutable value semantics; aliases never persist instead of ProviderId; stable IDs are CLR-independent.
- **Tests / manual checks:** Equality/hash/validation and stable-identifier tests; malformed values rejected.
- **Remaining limitations:** No provider/store I/O or lifecycle orchestration.

---

## Phase 3 — Algorithm policy and local primitives

- **Purpose:** Provide local primitives and an explicit algorithm policy catalog.
- **Changes:** Implement secure random, hash, fixed-time compare, HMAC, HKDF, PBKDF2, Advanced local primitive layer, Recommended/Supported/LegacyReadOnly policy.
- **Dependencies:** Phase 2 where identifiers are needed.
- **Acceptance criteria:** Known-answer vectors pass; no silent downgrade; legacy/new-operation policy is enforced.
- **Tests / manual checks:** Authoritative vectors and negative policy tests.
- **Remaining limitations:** No managed keys, AEAD orchestration, or provider routing yet.

---

## Phase 4 — Sensitive memory model

- **Purpose:** Define ownership and bounded raw-material access before providers expose material.
- **Changes:** Implement scoped material access, SensitiveMaterialLease, zeroization, and import ownership semantics.
- **Dependencies:** Phases 1-3.
- **Acceptance criteria:** Deterministic disposal; no meaningful ToString or implicit byte[] conversion; only owned buffers are wiped.
- **Tests / manual checks:** Dispose, exception-path, and copy-minimization tests.
- **Remaining limitations:** Cannot guarantee erasure of external/runtime/OS copies.

---

## Phase 5 — Logical/exact key handles and typed capabilities

- **Purpose:** Separate forward-use identity from exact historical identity.
- **Changes:** Implement logical/exact handles and Encryption/Mac/Derivation/Asymmetric typed views without default raw exposure.
- **Dependencies:** Phases 2 and 4.
- **Acceptance criteria:** Logical handles do not cache stale Active; exact handles never move; capability mismatch rejected.
- **Tests / manual checks:** Resolver/rotation simulations and exact-handle stability tests.
- **Remaining limitations:** No persistent lifecycle or concrete provider backend yet.

---

## Phase 6 — Pure key lifecycle state machine

- **Purpose:** Encode lifecycle invariants as deterministic domain logic before persistence.
- **Changes:** Implement transition matrix, Pending/Activate/Rotate planning/Retire/Discard/Delete/ForceDelete, version reservation, retention and idempotency classification.
- **Dependencies:** Phases 2 and 5.
- **Acceptance criteria:** Active invariant preserved; ForceDeleteVersion cannot remove current Active; discard ends in Deleted; version reuse impossible inside represented history.
- **Tests / manual checks:** Pure unit/property-style transition tests; no I/O.
- **Remaining limitations:** No durable effects or provider dispatch.

---

## Phase 7 — Provider backend contracts and registry

- **Purpose:** Establish external provider boundary before the software-store adapter.
- **Changes:** Define IKeyProviderBackend and minimal external supporting contracts in Abstractions; implement immutable registry, alias resolution, duplicate validation, exact routing.
- **Dependencies:** Phases 2 and 5.
- **Acceptance criteria:** External providers reference Abstractions only; duplicate IDs/aliases rejected; no scan-all-providers routing; no IKeyStore dependency yet.
- **Tests / manual checks:** Registry/routing/capability contract tests with fake providers.
- **Remaining limitations:** Software provider adapter intentionally absent.

---

## Phase 8 — Storage and protection contracts

- **Purpose:** Freeze software persistence and at-rest protection boundaries.
- **Changes:** Define IKeyStore, revisions/results, atomic name claim/create, material primitives, rollback capability, optional nonce-state contract, IKeyStoreProtector, ProtectorReference, protection-purpose model.
- **Dependencies:** Phases 2, 6, 7.
- **Acceptance criteria:** Custom store/protector references Abstractions only; nonce allocator is optional; root protection material cannot be exported by contract.
- **Tests / manual checks:** Compile fake external implementations; concurrency/result semantics tests.
- **Remaining limitations:** No concrete FileSystem persistence yet.

---

## Phase 9 — Operational key orchestration and software provider adapter

**Implementation checkpoint (2026-10-09):** software lifecycle adapter, CAS composition, authenticated provisional metadata and fault-injection tests have been added. .NET compilation/NUnit and durable store behavior remain unverified; acceptance gate is open.

- **Purpose:** Connect lifecycle rules to persistent provider/store operations.
- **Changes:** Implement software backend plus Create/Get/Find/GetOrCreate/CreateVersion/Activate/Rotate/Retire/Discard/Delete/ForceDelete, optimistic concurrency, safe retries, loser cleanup, durable name release.
- **Dependencies:** Phases 6-8.
- **Acceptance criteria:** Operational workflows cannot bypass the pure state machine; one provider/name produces one winner across actors; cancellation/commit boundaries documented.
- **Tests / manual checks:** Fake-store concurrency/conflict/failure-injection tests including losing-creator cleanup.
- **Remaining limitations:** Concrete durable FileSystem guarantees are not available yet.

---

## Phase 10 — AEAD nonce policy engine

- **Purpose:** Make managed AES-GCM nonce safety explicit and capability-driven.
- **Changes:** Implement Randomized, RollbackProtectedDeterministic, ProviderManaged selection, bounds/exhaustion, imported-key restrictions, restore behavior.
- **Dependencies:** Phases 7-9.
- **Acceptance criteria:** Rollback-unprotected storage cannot select deterministic; test rollback-protected backend reserves unique ranges; unknown-history imported AES restricted.
- **Tests / manual checks:** Parallel/restart/crash range tests, CSPRNG nonce tests, overflow/exhaustion, external-restore simulation.
- **Remaining limitations:** Whole-buffer managed encryption payload/service not yet complete.

---

## Phase 11 — Persistent schemas and migrations

- **Implementation status (2026-10-09):** LSMD v2, authenticated legacy decoder, explicit in-memory migration, LSPB/LSNC schemas and golden tests implemented; .NET build and NUnit not yet verified.

- **Purpose:** Create stable versioned persistence independent of runtime classes.
- **Changes:** Implement persisted DTOs, metadata format version, high-water mark, protector bootstrap/reference, optional rollback-protected nonce state mapping, migration chain, unknown-newer rejection.
- **Dependencies:** Phases 2, 8-10.
- **Acceptance criteria:** Golden formats stable; migrations deterministic; future format fails closed; crash recovery preserves current-history monotonic state.
- **Tests / manual checks:** Golden-file, migration, corruption, future-version, mapping round-trip tests.
- **Remaining limitations:** No concrete filesystem path/permission implementation yet.

---

## Phase 12 — FileSystem store base

**Implementation checkpoint (2026-10-09):** protected single-snapshot filesystem prototype, shared file lock, atomic replace, strict codec, corruption tests, and experimental-only write gate added. Actual .NET build, NUnit execution, cross-process OS tests, and Phase 13 platform hardening remain unverified.

- **Purpose:** Provide a protected default software store from its first implementation.
- **Changes:** Implement isolated root, path validation, protected envelopes, atomic name claim, conditional replace, temp/flush/validate/replace, revisions, recovery, cleanup using IKeyStoreProtector.
- **Dependencies:** Phases 8 and 11.
- **Acceptance criteria:** No raw secure-default material path; no plaintext fallback; cross-process name claim; no rollback-protected deterministic nonce claim.
- **Tests / manual checks:** Cross-process create/replace, crash/failure injection, envelope tamper/corruption tests.
- **Remaining limitations:** No production sensitive-data writes until Phase 13 platform hardening is complete: Phases 12+13 form one security gate.

---

## Phase 13 — FileSystem platform hardening

**Implementation checkpoint (2026-10-09):** Linux pinned-descriptor no-follow I/O, strict owner/mode/ancestor checks, `flock` and directory fsync; Windows owner/DACL and reparse checks. Platform test cases added but not executed; Windows handle-relative race hardening and production release validation remain **open**.

- **Purpose:** Enforce host filesystem safety assumptions.
- **Changes:** Implement Windows ACL validation/hardening, Unix modes, owner/inheritance checks, symlink/reparse protections, fail-closed initialization.
- **Dependencies:** Phase 12.
- **Acceptance criteria:** Unsafe roots/redirection rejected; newly created safe root is verified.
- **Tests / manual checks:** Platform integration tests for permissions, ownership, inheritance, symlink/reparse attacks.
- **Remaining limitations:** Does not itself provide a platform root protector.

---

## Phase 14 — Concrete platform protector implementation(s)

**Interim implementation (2026-10-09):** Windows DPAPI CurrentUser in `Laveyana.Security.Windows`, `LSWP` v1 envelopes, purpose/identity/AAD binding and native plaintext zeroization. Windows tests are authored but unexecuted. Other platforms have no built-in protector yet; .NET/Windows gates remain open.

- **Purpose:** Provide real safe protection for selected platforms.
- **Changes:** Implement chosen Windows/Android/etc. IKeyStoreProtector, stable ProtectorReference, purpose separation, opaque root protection secret.
- **Dependencies:** Phases 8, 12, 13.
- **Acceptance criteria:** Unavailable protector fails closed; Metadata and KeyMaterial contexts cannot be cross-used; root secret is not exposed.
- **Tests / manual checks:** Platform availability/restart/tamper/context-separation tests.
- **Remaining limitations:** Only selected platforms receive a concrete default protector.

---

## Phase 14A — Protector migration / re-protection

**Implementation snapshot (2026-10-09):** Exact-reference legacy-read/current-write router, per-key full-aggregate CAS re-protection and recoverable FileSystem snapshot/bootstrap migration are implemented, with fail-closed compromised status and fault-injection tests written. .NET 10 compilation, NUnit, Windows and filesystem production security gates remain open.

- **Purpose:** Change at-rest protection without pretending cryptographic key material rotated.
- **Changes:** Implement legacy protector read, current protector write, explicit re-protect, recovery-safe replacement, legacy/compromised status handling.
- **Dependencies:** Phase 14 and persisted envelope format.
- **Acceptance criteria:** Same KeyReference/material before and after; old envelope survives failure; protector compromise remains distinct from key rotation.
- **Tests / manual checks:** Failure injection around re-protection; legacy-read/current-write tests.
- **Remaining limitations:** Re-protection cannot undo prior compromise of cryptographic material.

---

## Phase 15 — Managed cryptographic result values

**Interim implementation (2026-10-09):** `Laveyana.Security.Abstractions.Payloads` provides immutable `EncryptedPayload`, `DetachedEncryptedPayload`, `SignaturePayload`, `MacResult`, `ManagedPayloadCodec` and `EncryptedPayloadAssociatedData`. `LEP1`, `LDP1`, `LSP1`, `LMR1` v1 records reject invalid bounds, versions, flags, identities, algorithms and trailing bytes. AEAD uses canonical domain-separated AAD including the exact key, algorithm, nonce, ciphertext length and *external* application AAD. Creation/decoding is **not** cryptographic authentication; Phases 16/17 supply executable cryptographic operations (acceptance pending real build/tests). Golden fixtures and NUnit are written, .NET 10 build/tests remain unverified. End-to-end logical-operation exact-version selection is implemented in Phase 16 (testing remains open).

- **Purpose:** Give managed crypto operations stable self-describing historical identity.
- **Changes:** Implement immutable EncryptedPayload, managed/detached variants, SignaturePayload, MacResult, exact-reference recording, internal authenticated metadata, external AAD, codecs/versioning.
- **Dependencies:** Phases 2, 5, 9-11.
- **Acceptance criteria:** Logical forward operations record the exact version actually used; historical operations resolve exact references; critical fields immutable/versioned.
- **Tests / manual checks:** Tamper, unknown-format, wrong-AAD/key, codec fuzz tests.
- **Remaining limitations:** High-level symmetric service is the next phase.

---

## Phase 16 — Symmetric encryption high-level API

**Interim implementation (2026-10-09):** `IAuthenticatedEncryptionBackend` and `SoftwareKeyProviderBackend` provide AES-256-GCM active-version encryption, historical exact-version authentication/decryption, detached execution and narrow TryDecrypt. Phase 10 nonce policy is enforced with the 16 MiB Phase 15 payload limit; ChaCha20-Poly1305 execution is explicitly deferred pending nonce policy support. Additional NUnit integration tests are written but not run, and external rollback/protection and platform security gates remain open.



- **Purpose:** Expose safe whole-buffer authenticated encryption/decryption.
- **Changes:** Implement AES-GCM default, supported alternatives, managed/detached paths, Decrypt, TryDecrypt using the nonce engine and EncryptedPayload.
- **Dependencies:** Phases 9, 10, 15.
- **Acceptance criteria:** Ordinary consumer manages no nonce/tag; strategy follows declared capabilities; failure categories are preserved; exhaustion fails closed.
- **Tests / manual checks:** Known vectors, authentication negatives, unsupported capability, budget exhaustion, rotation/historical decrypt tests.
- **Remaining limitations:** Encrypted streaming remains gated/deferred.

---

## Phase 17 — MAC and signature APIs

- **Purpose:** Expose managed MAC/signing with exact historical identity.
- **Changes:** Implement MAC compute/verify, signature sign/verify, provider-backed async dispatch, public/private typed views.
- **Dependencies:** Phases 5, 7, 9, 15.
- **Acceptance criteria:** Invalid signature/MAC is an expected negative result; provider failures remain exceptions.
- **Tests / manual checks:** Known vectors, historical verify after rotation, capability mismatch, provider-failure tests.
- **Remaining limitations:** Asymmetric confidentiality remains separate and gated.

---

## Phase 18 — Key agreement and derivation

- **Purpose:** Provide derived capabilities without exposing raw shared secrets by default.
- **Changes:** Implement ECDH default, mandatory KDF, canonical domain-separated derivation context, ephemeral derived capabilities, explicit materialization.
- **Dependencies:** Phases 3-5, 7, 9.
- **Acceptance criteria:** High-level key agreement never returns raw shared secret; different purposes use different contexts.
- **Tests / manual checks:** Known vectors/interoperability, context separation, lifetime/zeroization tests.
- **Remaining limitations:** PQC KEM is not a Generation 1 default.

---

## Phase 19 — SealedPayload / standardized hybrid encryption

- **Purpose:** Add high-level asymmetric confidentiality only after a dedicated security gate.
- **Changes:** Select an RFC 9180-compatible construction/implementation, exact suite/encoding/info/AAD/limits/vectors; complete focused security review; only then implement Seal/Open/SealedPayload.
- **Dependencies:** Phases 5, 7, 15 plus successful gate.
- **Acceptance criteria:** Conformance/interoperability vectors pass; review complete; raw RSA arbitrary-payload encryption is not the high-level default.
- **Tests / manual checks:** Suite vectors, tamper, recipient mismatch, policy tests.
- **Remaining limitations:** If no acceptable strategy exists, phase remains unsupported/deferred and does not block the rest of the release.

- **Phase 19 evidence/status (2026-10-09):** RFC 9180 Appendix A.3.1 Base test vector checked offline (six ciphertexts + 14 negative cases), but no trusted .NET HPKE provider, interop, wire-format review or .NET SDK/NUnit. **DEFERRED / UNSUPPORTED** by security gate. See `Laveyana.Security.HpkeGate.md`; nothing advertises Seal/Open capabilities.

---

## Phase 20 — Streaming

**Implementation snapshot (2026-10-09):** bounded-buffer SHA-256/384/512 and versioned HMAC-SHA-256/384/512 streaming, post-EOF revision check and negative NUnit scenarios are prepared. Encrypted segmented AEAD remains DEFERRED/UNSUPPORTED pending a dedicated security gate. .NET SDK/tests have not run. See `Laveyana.Security.StreamingGate.md`.


- **Purpose:** Provide bounded-memory streaming primitives without unsafe ad-hoc framing.
- **Changes:** After protocol gate, implement streaming hash/MAC and approved segmented AEAD with completion/truncation/cancellation semantics and format versioning.
- **Dependencies:** Phases 3, 15-18 and successful AEAD streaming gate.
- **Acceptance criteria:** Reorder/duplicate/remove/truncate/splice detected; nonce/key limits enforced; bounded memory; no unauthenticated completion.
- **Tests / manual checks:** Negative stream corpus, large-stream tests, cancellation, fuzzing.
- **Remaining limitations:** Encrypted streaming may remain deferred if the gate is not satisfied.

---

## Phase 21 — Secrets

**Implementation snapshot (2026-10-09):** `ISecretProvider` (Find/Get only), `SecretReadResult`, callback-scoped `SecretHandle`, exact-ID `SecretProviderRegistry`, optional `ISecretManagementProvider` and fail-closed descriptor capabilities are prepared with NUnit negative tests. No built-in secret persistence/provider is implied. .NET compilation and NUnit are not yet confirmed.

- **Purpose:** Implement read-oriented secret capabilities without copying the Keys lifecycle unnecessarily.
- **Changes:** Implement SecretId/Reference/Descriptor/Handle, multiple providers, deterministic routing, scoped access, optional management extension only where a provider needs it.
- **Dependencies:** Phases 4, 7 and shared registry/value infrastructure.
- **Acceptance criteria:** No default long-lived string/byte[]; deterministic routing; base provider requires only Get/Find.
- **Tests / manual checks:** Routing, absence semantics, lease cleanup, optional-management capability tests.
- **Remaining limitations:** Universal SecretVersion intentionally remains absent.

---

## Phase 22 — Dependency injection

- **Purpose:** Provide validated composition without moving business logic into DI.
- **Changes:** Implement AddSecurity, AddSecurityDefaults, provider/protector registration, alias resolution, capability/lifetime validation, immutable settings snapshot, platform-safe presets in platform packages.
- **Dependencies:** Operational core and at least one selected safe protector for usable defaults.
- **Acceptance criteria:** Missing protector, duplicate identities, invalid capability/lifetime combinations fail at startup; no unsafe fallback.
- **Tests / manual checks:** Service-provider validation, lifetime/captive dependency, manual-vs-DI behavior tests.
- **Remaining limitations:** Automatic rotation worker remains off by default.

---

## Phase 23 — Rotation policy and optional worker

- **Purpose:** Add policy-driven rotation without hidden runtime ownership.
- **Changes:** Implement TimeProvider-based policy evaluation, manual rotation engine, explicit opt-in hosted worker using the same engine.
- **Dependencies:** Phases 6, 9, 22.
- **Acceptance criteria:** Default starts no worker; manual/automatic semantics match; shutdown/cancellation documented.
- **Tests / manual checks:** Fake-time due/overdue, concurrent rotation, host-shutdown tests.
- **Remaining limitations:** Rotation policy does not prove external data is ready for old-key deletion.

---

## Phase 24 — Provider migration primitives

- **Purpose:** Support controlled provider migration without mutating old reference meaning.
- **Changes:** Create destination provider/new KeyId, transfer/regenerate according to exportability, validate/activate, expose checkpoints, retire/delete source after guards.
- **Dependencies:** Phases 7, 9, 15-18.
- **Acceptance criteria:** Old references immutable; no hidden redirect; non-exportable source handled without forced raw export; failures recoverable.
- **Tests / manual checks:** Exportability matrix, failure checkpoints, coexistence, application-reference migration tests.
- **Remaining limitations:** Application owns dependent-data/reference migration transaction semantics.

---

## Phase 25 — Observability

- **Purpose:** Add diagnostics after stable operations exist without leaking sensitive data.
- **Changes:** Implement structured logging, metrics, ActivitySource, optional audit events with low-cardinality safe dimensions.
- **Dependencies:** Operational APIs and result taxonomy.
- **Acceptance criteria:** No sensitive payload/material or default high-cardinality identity labels; application chooses telemetry backend.
- **Tests / manual checks:** Secret-scanning/manual review, cardinality, tracing-correlation tests.
- **Remaining limitations:** Core does not persist a durable audit database/file.
- **Implementation status (2026-10-10):** Phase 25 code and tests prepared; static checks passed. .NET 10 build/NUnit not executed, so acceptance remains open. Audit is best effort only.

---

## Phase 26 — Final documentation synchronization

- **Purpose:** Synchronize repository documentation with implemented Generation 1 behavior.
- **Changes:** Synchronize actual APIs/Architecture/TechnicalSpecification/Roadmap/DecisionLog in EN/RU; produce README after real code, CHANGELOG before the first public release, and LICENSE only after explicit owner selection.
- **Dependencies:** All release-intended implementation phases.
- **Acceptance criteria:** EN/RU documents remain equivalent and match actual public API/lifecycle/provider/storage behavior.
- **Tests / manual checks:** Cross-language checklist, API/doc link validation, source-comment language scan.
- **Remaining limitations:** Deferred HPKE/streaming capabilities remain explicitly marked unsupported if gates did not pass.

- **Implementation checkpoint (2026-10-10):** EN/RU README, CHANGELOG, design-state summaries, release-gate wording, decision-coverage notes and an automated documentation checker were prepared from the Phase 25 source baseline. No cryptographic source behavior changed. Link/API/phase/decision structural checks can run locally and in CI. Actual .NET/NUnit/security acceptance remains pending.

---

## Phase 27 — Full security audit

> **Partial review snapshot (2026-10-10):** static and manual source checks performed; mutable AAD/message races patched, but regression tests unrun. Build, live fuzz, platform/cross-process checks and independent review are not complete. **NO-GO**. [Detailed findings](../audit/Laveyana.Security.Phase27.SecurityAudit.md).


- **Purpose:** Perform a release-gate review of the complete system.
- **Changes:** Audit dependency graph, public surface, secret exposure, concurrency, lifecycle, capability mismatches, persistence/recovery, permissions, formats; fuzz codecs; run integration suite.
- **Dependencies:** All release-intended implementation phases.
- **Acceptance criteria:** No known violated security invariant; documented threat-model limitations explicit; Generation 1 acceptance criteria satisfied.
- **Tests / manual checks:** Full test matrix, fuzz corpus, failure injection, cross-process/platform integration, manual public-surface/security review. Check the API compatibility gate against an existing published baseline (if any), clean CI/build and document consistency.
- **Remaining limitations:** Documented infrastructure limits such as undetectable rollback without external authority remain real limits.

---

## Release gate

Phase 27 is mandatory. Phase 19 (HPKE) and encrypted-AEAD functionality within Phase 20 remain release-optional if their gates fail; explicitly document them as unsupported/deferred, with no unsafe replacement protocol. FileSystem Phases 12 and 13 jointly constitute the writable-store security gate. No README/CHANGELOG/LICENSE placeholders are generated prematurely.

**Phase 17 implementation snapshot (2026-10-09):** `SoftwareKeyProviderBackend` implements full-length HMAC-SHA-256/384/512 with exact Active/Retired version verification, fixed-time tag comparison and strict error separation. Optional `IManagedMacBackend` / `IManagedSignatureBackend` contracts and exact-ID registry routes are available. `ManagedSignatureBackend` executes ECDSA P-256 or RSA-PSS through injected versioned key operations. An owned, process-local `EphemeralSignatureKeyOperations` is provided for testing/ephemeral use only; durable asymmetric key management and revocation-aware execution remain **deferred**, and .NET compilation/NUnit are **not verified**. No production gate is closed.

**Phase 18 implementation snapshot (2026-10-09):** Optional `IManagedKeyAgreementBackend`/`IVersionedKeyAgreementOperations` with `ManagedKeyAgreementBackend` plus process-local `EphemeralEcdhKeyOperations` implement P-256 ECDH → mandatory HKDF-SHA-256. `DerivationContext`, `DerivedKeyLease`, opt-in export policy, protected symmetric `IManagedDerivationBackend`, typed operations and exact-ID routing are implemented. Independent vectors and negative tests are written, **not run**. Peer authentication, durable asymmetric keys, cross-process revocation, production security gate and .NET build/NUnit remain open; PQC KEM is not default.



## Phase 22 — DI and composition implementation (2026-10-09)

`Laveyana.Security.DependencyInjection` now provides `AddSecurity(Action<SecurityCompositionBuilder>)`,
`AddSecurityDefaults(...)`, an immutable `SecurityCompositionSnapshot`, explicit key/secret
backends, an optional store, an authenticated protector, an optional nonce allocator, and
`TimeProvider`. There is no implicit file store, software key generation, platform scanning,
plaintext fallback, or automatic rotation worker. Defaults require an explicitly selected
protector; a software backend requires both an explicitly selected store and protector.

Startup composition rejects duplicate provider IDs, conflicting aliases, unknown capability
requirements, transient/scoped typed dependencies, and repeated registration. Typed providers
must already be registered as singletons. Provider-wide capabilities are dynamic: required
capabilities are checked by a startup-only `IHostedService` when using .NET Host, or by
calling `SecurityCompositionSnapshot.ValidateCapabilitiesAsync` explicitly without a host.
All operations must still authorize capabilities and key state at execution time.

**Limits:** External factory registrations can hide captive dependencies; use DI scope/build
validation in the host. FileSystem requires an explicit asynchronous `OpenAsync` before
composition (never sync-over-async). A Windows-specific convenience package preset is not
included yet; explicitly passing a `WindowsDpapiUserProtector` is supported. The .NET SDK
and NUnit execution were unavailable; production acceptance and previous FileSystem
security gates remain open.


## Phase 23 — explicit key rotation policy and optional hosted worker (2026-10-09)

`RotationPolicy`, `RotationAssignment` and `RotationEngine` are available in the core
`Laveyana.Security.Rotation` namespace. A schedule includes a trusted UTC activation
instant and the exact **expected active version**. Due/overdue is evaluated via the
injected `TimeProvider`; there is no assumed key creation time or implicit enumeration.
`RotateNowAsync` and `RotateIfDueAsync` use the same version-fenced executor.
`IConditionalKeyRotationBackend.RotateIfCurrentAsync` requires a backend-level atomic
active-version precondition. The software backend enforces that precondition in the
same state snapshot as its store compare-and-swap write: concurrent rotations cannot
successfully create two successive versions from one assignment.

`AddSecurity` / `AddSecurityDefaults` never start a worker. Only the explicit
`AddSecurityRotationWorker(IRotationWorkSource, pollInterval)` registration installs
`RotationWorker`. The application supplies `IRotationWorkSource` with **durable,
atomic, one-shot claims of due work before execution**; an in-memory queue is not a production
implementation. Claimed work is never automatically reissued after a crash or an
ambiguous commit. `RecordResultAsync` persists an unambiguous outcome; errors fault
the worker for operator reconciliation. A fresh assignment for the new active version
must be persisted by the application. Host cancellation is forwarded through all
steps; no background work is owned by the core engine. Neither the worker nor the
policy authorizes key operations: the caller, schedule source and backend enforce
appropriate access controls.

```csharp
using Laveyana.Security.Rotation;
using Laveyana.Security.DependencyInjection.Rotation;

// The caller persists a trusted activation time and expected version.
RotationAssignment assignment = new(handle, activeVersion, activatedAtUtc,
    new RotationPolicy(TimeSpan.FromDays(30)));
RotationAttemptResult outcome = await rotationEngine.RotateIfDueAsync(assignment, cancellationToken);

// Explicit opt-in, only with an application-owned durable work source:
services.AddSecurityRotationWorker(durableRotationSource, TimeSpan.FromMinutes(1));
```

**Open gates:** The work-source atomicity/durability contract has no bundled
production implementation; an uncertain commit needs manual reconciliation, not
blind retry. Clock anchoring and the schedule's authorization come from the
application. Rotation does not prove historical ciphertext is ready for deletion.
.NET 10 build, NUnit, multi-host and platform security gates remain unverified.


## Phase 24 — explicit provider migration boundaries

`ProviderMigrationRequest` freezes a source **exact Active** `KeyReference`, a distinct
`ProviderId`, target name, required capabilities and an explicit mode. The
`ProviderMigrationOrchestrator` executes `PlanAsync` → `PrepareAsync` →
`ValidateAsync` → `ActivateAsync` → `ConfirmApplicationCutover` with immutable
`ProviderMigrationCheckpoint` values. Checkpoints contain no key bytes; their
provenance and ordering must be authenticated and persisted by the application.
`ProviderMigrationCheckpoint.Restore` is a validation helper, not a proof of
journal trustworthiness. New software keys are already Active at preparation;
`ActivateAsync` for them only checks the exact version, not an application cutover.

The `SoftwareMigrationDestination` adapter supports **regeneration only**, with a
new `KeyId` and independent random material. Provider-native transfer is opt-in
and uses `IProviderNativeMigrationSource` plus
`IProviderNativeMigrationDestination` without a public plaintext export API.
Both providers must enforce their own trust, transport security, authorization,
atomicity and replay protection; these implementations are not bundled. The
orchestrator checks exact source/destination identities, kind, algorithm and
required operations between steps, but preflight cannot guarantee a provider's
backend policy or eliminate races without that provider's own atomic operations.

Cutover is **not** a rewrite of persisted `KeyReference` or ciphertext: it requires
an explicitly matching `MigrationCutoverReceipt` after the application durably
migrates dependent data and references. Source retirement/deletion is optional and
requires provider-owned `IProviderMigrationSourceLifecycle` enforcement of
retention, current-version fencing and surviving dependencies. The software
backend deliberately does not implement it, and no force-delete fallback exists.

For each mutating step, the application must first durably record its pending
intent in a CAS journal, then persist the acknowledged checkpoint. Any uncertain
outcome (including checkpoint persistence) blocks blind retries; reconcile
provider state and the application journal before continuing. This library does
not provide a cross-provider transaction, distributed lock, application data
re-encryption or rollback-resistant durable migration journal. Build/NUnit and
production security gates remain open.
