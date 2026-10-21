# Laveyana.Security — Architecture

**English** | [Русский](Laveyana.Security.Architecture.ru.md)

> Status: **final Generation 1 architecture baseline**.
>
> Implementation must preserve the boundaries and invariants in this document. Reopening a fixed decision requires a new technical reason and a Decision Log entry.


> **Implementation and verification checkpoint (2026-10-16; H01):** Seven project sources and public APIs are present. GitHub Actions `Source & docs`, Release builds and NUnit passed on Windows and Ubuntu. The previously missing build/test baseline is resolved, but Phase 27 adversarial security acceptance is **not** complete. FileSystem remains experimental; HPKE `Seal/Open` and encrypted streaming AEAD remain unsupported. Historical “tests not executed” remarks in phase narratives describe those phases, not current CI. See [README](../../README.md), [Roadmap](Laveyana.Security.Roadmap.md) and [CHANGELOG](../../CHANGELOG.md).

## 1. Architectural model

`Laveyana.Security` separates four layers of responsibility:

```text
Consumer contracts / stable values
        ↓
Domain orchestration / policy / lifecycle
        ↓
Provider and storage extension boundaries
        ↓
Concrete software/platform/HSM/remote implementations
```

The ordinary consumer works with capability-oriented high-level APIs and does not manually manage dangerous cryptographic details.

## 2. Dependency graph

```text
Laveyana.Security.DependencyInjection
        ├───────────────┐
        v               v
Laveyana.Security   Laveyana.Security.FileSystem
        │               │
        └───────┬───────┘
                v
Laveyana.Security.Abstractions
```

Platform/provider packages also depend downward on `Laveyana.Security.Abstractions`. A platform package may additionally compose DI/FileSystem when it owns a platform-safe preset, but the cross-platform core never depends on platform packages.

Forbidden directions:

- `Abstractions → Security/FileSystem/platform`;
- `FileSystem → Security` merely to obtain `IKeyStore`;
- provider package → `Security` merely to obtain backend contracts;
- cyclic `ProjectReference` graphs.

## 3. Logical modules

The main assembly remains one technical unit but has three logical modules:

```text
Laveyana.Security.Cryptography
Laveyana.Security.Keys
Laveyana.Security.Secrets
```

No separate `.csproj` is created only because a namespace exists.

### Cryptography

Algorithm policy, safe defaults, local primitives, high-level payload semantics, validation, dispatch, and provider-backed operations.

### Keys

Key identity, typed capabilities, lifecycle, provider registry, rotation, retention, delete, provider migration, and software-provider orchestration.

### Secrets

Read-oriented secret providers, opaque secret handles, and controlled material access.

## 4. Public API layers

### Consumer-facing abstractions

`Laveyana.Security.Abstractions` contains every type required in ordinary consumer-facing signatures, including:

- stable identifiers and references;
- descriptors and lifecycle/capability values;
- logical and exact-version capability contracts;
- high-level cryptographic service contracts;
- high-level key/secret management contracts;
- `EncryptedPayload`, `SignaturePayload`, `MacResult`;
- typed result/status values and contract exceptions.

### Extensibility-facing abstractions

The same assembly also contains deliberate cross-assembly extension points in dedicated namespaces:

- `IKeyProviderBackend`;
- `IKeyStore`;
- `IKeyStoreProtector`;
- optional rollback-protected AEAD nonce-state contract;
- only the minimum supporting contexts/results/capabilities required by external implementations.

Serializers, locks, journals, internal state machines, orchestration helpers, and implementation-only validators stay internal.

## 5. Key aggregate

Conceptual logical-key aggregate:

```text
LogicalKey
├── ProviderId
├── KeyId
├── KeyName?               # runtime/application alias
├── KeyKind / capabilities
├── LogicalState
├── NextVersion / HighWaterMark
└── Versions[]
    ├── KeyVersion
    ├── Algorithm + parameters
    ├── VersionState
    ├── timestamps
    └── provider-owned material reference/capability
```

The word `material` never implies that raw bytes must exist in-process. HSM, OS-backed, remote, and non-exportable implementations can keep private material fully opaque.

## 6. Logical vs exact capabilities

Forward-use capability:

```text
EncryptionKey (ProviderId + KeyId)
        ↓ resolve current Active version
Exact version (ProviderId + KeyId + KeyVersion)
        ↓ dispatch
Encrypt
        ↓
EncryptedPayload records the exact KeyReference used
```

Historical-use capability:

```text
EncryptedPayload / SignaturePayload / MacResult
        ↓ exact KeyReference
resolve exact historical provider/key/version
        ↓
decrypt / verify
```

Rotation therefore changes future forward resolution but never changes the meaning of already-persisted references.

Logical handles must not cache an Active version across rotation. Exact handles never move automatically.

## 7. Lifecycle state machine

### Logical key

```text
Create
  ↓
Active ──RetireKey──> Retired ──DeleteKey──> Deleted
  │
  └── ForceDeleteKey (Advanced destructive path) ───> Deleted
```

### KeyVersion

```text
CreateVersion
   ↓
Pending ──Activate──> Active ──replacement / RetireKey──> Retired ──DeleteVersion──> Deleted
   │                    │
   └── Discard ────────>Deleted
                        └── ordinary delete forbidden while current Active
```

Activation replacement is one atomic/recoverable domain transition:

```text
old Active → Retired
new Pending → Active
```

A standalone `RetireVersion(current Active)` cannot leave a logical `Active` key without an Active version. Consumers must use replacement activation or `RetireKey`.

## 8. KeyVersion reservation

Version identity is irreversible within the represented authoritative history:

```text
v1 created
v2 created
v2 discarded
v3 created
next version = v4
```

The aggregate/store persists sufficient high-water state to prevent reuse during normal operation and supported crash recovery.

This guarantee is explicitly bounded by rollback characteristics: restoring an older valid snapshot of a rollback-unprotected store can roll back the high-water state.

### Phase 6: pure lifecycle planning boundary

The implementation-only `Laveyana.Security.Lifecycle.KeyLifecyclePlanner` operates on validated, immutable snapshots and produces immutable transition plans. It has no storage dependency, no time source and no provider dispatch. Planned state replacements are atomic **only as domain calculations**. Provider orchestration (Phase 9) must commit plans and material changes transactionally with optimistic revision checks against a trusted authoritative store (Phase 8). The provider must reconcile ambiguous commit outcomes before retries; a pure operation's state-based no-op is not a cross-process idempotency key. Current Active cannot be removed with `ForceDeleteVersion`, while explicit `ForceDeleteKey` cascades consistently. Retention comes from authoritative state; high-water mark persistence and name release remain store responsibilities. A rollback-unprotected backup restore does not provide global monotonicity.

## 9. Provider registry and routing

Runtime composition produces an immutable registry:

```text
ProviderAlias ──resolve──> ProviderId ──route──> IKeyProviderBackend
```

Rules:

- aliases and IDs are independently unique;
- duplicates are startup/configuration errors;
- `KeyReference` routes directly by stable `ProviderId`;
- there is no scan-all-providers lookup;
- changing an alias mapping does not alter persisted reference meaning.

Provider capabilities are granular. A cryptographic operation is legal only when:

```text
key policy allows operation
AND
provider declares the required capability
```

## 10. Provider migration

Provider migration creates a new cryptographic generation:

```text
Source ProviderId A / KeyId A
        ↓
Destination ProviderId B / KeyId B
```

The existing KeyId is never moved between providers. Old references remain immutable and may coexist with destination references during migration.

If source material is non-exportable, migration may require application data re-cryptography or a provider-native transfer capability rather than raw material export.

## 11. Software provider boundary

```text
Laveyana.Security orchestration
        ↓
SoftwareKeyProviderBackend
        ↓
IKeyStore
        ↓
FileSystem or custom software store
```

The store owns persistence/consistency mechanics; Security owns lifecycle validity and cryptographic policy.

`GetOrCreate` correctness is enforced at the unique `(ProviderId, KeyName)` binding/aggregate creation boundary. Racing random KeyIds is insufficient.

## 12. Protected FileSystem architecture

```text
Laveyana.Security.FileSystem
        ↓ uses
IKeyStoreProtector
        ↓ implemented by
platform/custom protector
```

FileSystem persists conceptually:

```text
minimal bootstrap/routing header
protected metadata envelope
protected key-material envelope(s)
recovery/journal state where required
```

Bootstrap fields required to select `ProtectorReference`/envelope version may be cleartext, but must be cryptographically bound as authenticated context.

Metadata and material protection use distinct domain-separated purposes. A `master.key` stored beside encrypted keys is not an acceptable secure default unless that master key is itself protected by an independent security boundary.

## 13. FileSystem safety

**Implementation gate:** Until required owner/permission/path safety checks are implemented and tested on a target platform, the FileSystem store must not be treated as a production-safe writable key store. FileSystem foundation and platform hardening are one security release gate.


Initialization behavior:

- if the root is absent, create it, apply restrictive permissions, verify the result, and only then write sensitive files;
- if the root exists, validate owner, ACL/mode, inheritance, entry type, and reparse/symlink behavior;
- unsafe or unverifiable state fails closed.

Unix baseline:

```text
directory → 0700
secret file → 0600
```

Windows uses ACL/ownership validation appropriate to the deployment model and verifies the resulting ACL.

Normal filesystem delete means material is no longer reachable through the provider; it does not claim forensic secure erase.

## 14. Crash recovery vs external rollback

Two different recovery classes exist.

### Crash recovery

The current authoritative history exists but a write/workflow was interrupted. Recovery may use temp files, journal, checkpoint, transaction-equivalent replacement, resume, or rollback of the incomplete operation.

### External rollback / restore

A current valid store is replaced with an older but still valid/authenticated snapshot. A rollback-unprotected store may be unable to detect the event.

Therefore authenticated metadata is **not** rollback protection. Lifecycle state, version high-water marks, name bindings, usage counters, and deterministic nonce state may all roll back.

If an external restore is known, forward cryptographic use enters explicit reconciliation. Safe default:

```text
restored generation → historical/read-only where possible
fresh forward use   → new KeyId + fresh material
```

Deployments that require malicious-rollback detection must use an independent rollback-protected authority/backend.

## 15. AEAD nonce architecture

Strategy selection is capability-driven:

```text
provider safely owns AEAD nonce lifecycle
        → ProviderManaged

rollback-protected monotonic state exists
        → RollbackProtectedDeterministic

software key + rollback-unprotected store
        → Randomized

no safe strategy available
        → managed AES-GCM Encrypt unsupported
```

The deterministic allocator is a separate optional contract and is never part of mandatory `IKeyStore` CRUD.

### Randomized

Uses a fresh 96-bit CSPRNG nonce. It is the default for ordinary FileSystem storage because it does not rely on a rollback-able FileSystem counter.

### RollbackProtectedDeterministic

Requires both rollback protection and an atomic monotonic reservation capability bound to an exact `KeyReference`. Committed unused ranges after a crash are burned.

### ProviderManaged

The backend owns safe nonce semantics and returns the public metadata needed by the managed payload.

## 16. Payload architecture

Managed encryption result:

```text
EncryptedPayload
├── FormatVersion
├── AlgorithmId + public parameters
├── Nonce
├── Ciphertext
├── AuthenticationTag
└── exact KeyReference
```

Managed signature/MAC results similarly contain exact historical identity:

```text
SignaturePayload
MacResult
```

Security-critical fields are immutable and authenticated as internal metadata where cryptographically applicable.

Application-provided AAD is separate external context. Security authenticates it but does not interpret its domain meaning or persist it automatically.

## 17. Persistent schema architecture

Runtime/domain classes are not permanent schemas.

```text
Domain model
    ↓ mapping
Persisted Vn DTO
    ↓ codec
Protected envelope
```

Migration chain:

```text
V1 → V2 → V3 → ...
```

Migration performs strict old-version parse, validation, in-memory conversion, current-version validation, and safe persistence.

Stable persisted identifiers never depend on CLR type names, assembly-qualified names, or enum declaration ordering.

Unknown newer formats fail closed.

## 18. Secrets architecture

```text
SecretHandle (opaque)
        ↓
ISecretProvider
        ↓
UseMaterial(callback)
        or
SensitiveMaterialLease
```

The base secret model is read-oriented. Universal `SecretVersion` is intentionally absent; provider-specific versioning may exist as an optional capability.

`SensitiveMaterialLease` owns mutable memory, wipes owned memory on dispose, is not serializable/loggable, has no meaningful `ToString`, and has no implicit conversion to `byte[]`.

## 19. DI composition architecture

Manual construction remains a supported scenario.

DI composition:

```text
method-based settings DSL
        ↓ validation
immutable composition snapshot
        ↓
provider/protector registries
        ↓
thread-safe shared services
```

`AddSecurityDefaults()` is a common preset over the same model. It requires a pre-registered safe protector and never guesses a platform implementation through assembly scanning/reflection.

Platform packages may expose safe platform presets. Core/default composition starts no hidden background worker.

Optional automatic rotation uses Generic Host lifecycle and the same rotation engine as the manual path.

## 20. Integration boundary

`Laveyana.Security` provides capabilities. Domain libraries own domain semantics.

Example:

```text
Laveyana.Persistence.Security
├── decides what data is encrypted
├── constructs persistence-specific AAD
├── tracks data references
└── migrates/re-encrypts dependent data
        ↓
Laveyana.Security
└── crypto/key capabilities
```

Independent domains do not pretend to share one transaction if no real shared transaction exists. Cross-domain workflows use application-owned retry, compensation, journal, checkpoint, or recovery state.

## 21. Deliberate design gates

Two features remain intentionally gated rather than architecturally unresolved.

### Seal/Open

High-level asymmetric confidentiality is published only after selection of a standardized/analyzed HPKE-compatible construction, exact suites/encoding/info/AAD/limits, authoritative vectors, and focused security review. If the gate is not satisfied, the feature remains unsupported/deferred.

### Streaming AEAD

Encrypted streaming requires an analyzed segmented construction or a separately specified/reviewed protocol with nonce derivation, position binding, stream identity, splice/reorder/truncation protection, limits, vectors, and focused review.

No custom protocol is introduced merely to complete a checklist.

## 22. Normative invariants

The complete externally observable invariants and release gate are normative in [TechnicalSpecification](Laveyana.Security.TechnicalSpecification.md). This document owns mechanisms and dependency/ownership boundaries, not a second copy of the requirements.

### Phase 5 metadata-only resolution boundary

Typed views (`EncryptionKey`, `MacKey`, `DerivationKey`, `AsymmetricPublicKey`, `AsymmetricPrivateKey`) depend on an `IKeyMetadataResolver` which returns independent immutable logical/exact metadata snapshots. They validate declared capabilities, version consistency and key kind for discovery/preflight, but never return or authorize raw material. Resolution is **not** an authorization boundary: backend dispatch must perform its own current-state, policy, provider-capability and algorithm checks at actual operation time. A stale result must never be treated as an operation permit.

### Phase 7 — external provider contracts and immutable composition registry

`IKeyProviderBackend` and immutable `ProviderCapabilitySnapshot` are in `Laveyana.Security.Abstractions.Providers`, so external providers need no concrete Security/FileSystem/DI dependency. The interface extends `IKeyMetadataResolver` as a **metadata-discovery boundary**, not a giant cryptographic operations interface. Backend instances must retain one stable persistent `ProviderId` throughout their lifetime.

`Laveyana.Security.Providers.ProviderRegistry` captures immutable `ProviderRegistration` configuration in private ProviderId and optional alias mappings; duplicate identities and aliases are startup errors. `Route` and `IKeyMetadataResolver` reads dispatch solely by ProviderId, rejecting returned identity mismatches and backend identity changes. Provider capabilities are defensively copied, read-only declarations rather than policy authorization or operation reservations. The registry never probes for a different backend and cannot execute cryptographic operations. Durable workflows and software adapters follow in later phases.

### Phase 8 — atomic storage and protector boundaries

`Laveyana.Security.Abstractions.Storage.IKeyStore` is the durable software-store extension interface, separate from provider discovery. Create atomically claims `(ProviderId, KeyName)` with protected metadata and initial version material; CAS replace commits a new aggregate revision and its upsert/deletion set as one event; conditional delete removes the generation, all material and its name binding as one event. `ReadMaterialAsync` checks an exact aggregate revision, preventing material from silently being read under a different metadata snapshot. Revisions are per-aggregate, monotonic within an authoritative history, and name release occurs **only after** committed deletion. Persistent KeyId reuse remains forbidden, requiring a durable used-identity marker. The lifecycle planner and provider orchestrator, not store, determine which transitions are legal. Exceptions/cancellation near commit are ambiguous until authoritative reconciliation.

`Laveyana.Security.Abstractions.Protection.IKeyStoreProtector` independently encrypts and authenticates metadata and key material under distinct purposes and stable `ProtectorReference` generations. AAD construction binds exact key identity and metadata revision or exact material version. Envelopes are immutable opaque ciphertext containers, **not** authentication proof. Root protection keys are never exported; plain material crosses only as explicitly owned `SensitiveMaterialLease` input/output. No plaintext or weaker fallback is permitted. Independently rollback-resistant nonce allocation is an **optional** `IRollbackProtectedNonceAllocator`, never a mandatory CRUD store feature. No default filesystem backend is claimed rollback-protected; actual at-rest protection, permissions and crash recovery remain later implementations.

## Phase 9 implementation: protected software lifecycle orchestration

`Laveyana.Security.Software.SoftwareKeyProviderBackend` implements `IKeyProviderBackend` atop the external Abstractions-only `IKeyStore` and `IKeyStoreProtector`. All mutations are planned through internal `KeyLifecyclePlanner`; the adapter validates matching provider/name/key, authenticates the `LSM1` metadata snapshot with revision-scoped context, and commits protected state plus material changes under a single store CAS. Creation uses durable provider/name claim and revision 1; replace uses exactly `expected + 1` to pre-bind authenticated context. The backend never writes plaintext key material or returns it to callers.

`GetOrCreate` returns an existing generation only if algorithm, capabilities and initial retention match. The losing random candidate's temporary plaintext lease is disposed; store rejection must have no effects. Definite revision conflicts abort. Unknown commit outcomes throw `SoftwareKeyCommitUncertainException` and are never retried by this adapter. Name release requires committed aggregate delete. Retention and version high-water mark remain part of protected metadata; automatic reconciliation across external rollback is impossible without external authority. This backend advertises no executable cryptographic capabilities pending the operation API. Its temporary metadata wire format requires formal Phase 11 migration work before production persistence.

## Phase 10 implementation: AES-GCM nonce policy

The internal `Laveyana.Security.Nonce` package plans later provider operation paths without changing public external interfaces. Strategy selection uses trusted exact-key provenance and provider/authority guarantees; dispatch must independently revalidate lifecycle and restore state. Randomized uses a CSPRNG and a process-only per-key budget. Deterministic issuance requires a separately verified durable rollback-resistant authority that permanently reserves non-overlapping ranges; it serializes session issuance and refuses malformed or ambiguous commits. ProviderManaged never issues a local nonce. Known restoration of an older generation requires a new KeyId. Whole-buffer AES-GCM dispatch remains a later phase.

## Phase 11 — persistent schema boundaries

The runtime state machine retains lifecycle semantics; internal `SoftwareKeyPersistedRecord` maps it into stable wire values. `SoftwareKeyMetadataCodec` writes `LSMD` v2 and reads previously authenticated `LSM1` without mutating storage. Portable `LSPB`/`LSNC` record schemas are declared in `Abstractions.Persistence`, separate from the future FileSystem store, root-protector implementation and independently monotonic nonce authority.

## Phase 12 — FileSystem boundary implementation

`FileSystemKeyStore` depends only on Abstractions and a mandatory externally configured `IKeyStoreProtector`. A single snapshot is the transactional unit; the exclusive lock covers read/modify/replace, including durable KeyId tombstones. `LSPB` is only a bootstrap hint; current-state integrity depends on protector authentication of the snapshot manifest AAD. This does not imply historical snapshot rollback detection. The store does not bypass the provider lifecycle policy.

Phase 13 must close symlink/reparse/path component TOCTOU and directory durability assumptions before production writes. Explicit test-only opt-in remains disabled by default.

## Phase 13 — platform confinement boundary

The Linux filesystem backend pins the owner-controlled private directory and performs store-child I/O relative to its descriptor, using no-follow flags, ownership/type/mode checks, `flock`, and atomic directory-relative replacements followed by directory `fsync`. Untrusted ancestors and symbolic-link components are rejected. Windows performs owner/DACL and reparse checks (new stores receive protected ACLs), but path-based mutation still leaves a hostile-race threat. This is not a cross-platform production security certificate; the opt-in experimental flag and unresolved rollback boundary remain intact.


### Phase 14 — Windows DPAPI CurrentUser trust boundary

The platform assembly depends only on `Abstractions`. The application selects a protector explicitly, with no reflection-based discovery by FileSystem or DI. DPAPI CurrentUser binds identity, purpose and AAD through domain-separated optional entropy and protects the current Windows profile. Successful unprotection does not prove rollback resistance, safe pathname races, or isolation from other programs under the same user. `LSWP` v1/generation are stable; migration is Phase 14A. Unavailable DPAPI fails closed without plaintext fallback.


### Phase 14A — routing and atomic re-protection

`ProtectorGenerationRouter` belongs to the implementation assembly; custom providers and
protectors still depend on Abstractions alone. One immutable table routes exact historical
references only for authenticated reads; only its current protector may issue new envelopes.
Compromised/unknown generations are blocked, not silently downgraded. A separately invoked
`SoftwareKeyReprotectionService` authenticates metadata and each extant version, then CAS-
replaces metadata plus historical material together under the next revision. Deleted
versions have no material; tombstones remain in metadata. No automatic enumeration,
silent retries, partial upgrades or changes to crypto key identity occur. An ambiguous
commit requires authoritative read/reconciliation. Store guarantees and OS security gates
remain separate from this orchestration.


**Experimental FileSystem root migration:** The FileSystem store also authenticates its
whole `LSFS` snapshot separately from individual protected key records. Re-protecting
keys alone cannot migrate this outer layer. An existing store must first be opened with
`FileSystemKeyStore.OpenForMigrationAsync(options, router, legacyReference)` using
`EnableExperimentalWrites = true` and a **pinned, nonempty**
`ExpectedStoreInstanceId`. Ordinary `OpenAsync` stays strict. The explicit
`ReprotectRootAsync()` commits the current-generation snapshot first, then updates the
public `LSPB` bootstrap reference. The two filesystem replacements are **not one atomic
transaction**: a crash between them leaves a recoverable mixed state. Reopen using the
same pinned migration identity and trusted legacy reader, authenticate the snapshot,
and rerun the idempotent root migration. Other key-record writes are forbidden while
this migration session has not finished. Only after root migration may per-key
`SoftwareKeyReprotectionService` run over that store; after *all* live records migrate,
the store can be reopened using only the current protector. Root migration never
rewrites inner encrypted material or claims rollback protection.

### Phase 15 — result ownership, verification boundary and managed AAD

`Laveyana.Security.Abstractions.Payloads` defines ciphertext, detached metadata, signature and MAC values without a dependency on crypto provider implementations. Public `Export*Copy()` methods are the only way to retrieve buffers; no mutable backing memory is exposed. All forms require a persistent exact `KeyReference` rather than a runtime alias or logical handle. Four separate v1 binary record markers (`LEP1`/`LDP1`/`LSP1`/`LMR1`) make decoding unambiguous; future versions reject by default. Detached metadata commits to the ciphertext length.

The `EncryptedPayloadAssociatedData` canonical builder domain-separates AEAD internal metadata from bounded external application AAD. The sender and receiver must each call it with identical parameters during actual AEAD execution. An object or codec is never an authenticity oracle. Provider-specific encryption and exact-version resolution remain Phase 16; signature/MAC computation and verification are introduced in Phase 17, pending build/security acceptance. No untrusted payload fields grant authorization, capabilities, decryption or key export.


### Phase 16 — authenticated operation dispatch and revision consistency

`IAuthenticatedEncryptionBackend` is an opt-in Abstractions contract. A registry can route AEAD by stable ProviderId without interpreting runtime aliases or forwarding key material. `SoftwareKeyProviderBackend` owns policy enforcement, Active-version selection, revision-consistent protected material reads, AES-GCM execution and fixed historical-version decryption. Result codecs remain independent of execution. The nonce policy is invoked after material validation and uses its existing fail-closed choice: randomized for freshly generated material, or a separate verified rollback-safe allocator. ChaCha20-Poly1305 dispatch is deferred. Authentication failures return `null` only through TryDecrypt. All operations remain subject to the unresolved FileSystem/platform production gate.

### Phase 17 — managed MAC and asymmetric signature execution boundaries

Abstractions adds independent `IManagedMacBackend`, `IManagedSignatureBackend` and `IVersionedSignatureKeyOperations`. `ProviderRegistry` provides `RouteMac(logical/exact)` and `RouteSignature(logical/exact)` without alias-based dispatch or scanning. The symmetric software adapter authenticates its own stored metadata and exact-version key material at a single store revision, computes HMAC-SHA-2 and compares the full tag with `FixedTimeEquals`. It does not add asymmetric private keys to the existing symmetric persisted schema.

`ManagedSignatureBackend` composes trusted `IKeyProviderBackend` metadata resolution and a separate provider-owned executor. Sign requires Active + AsymmetricPrivate + capability; verify requires an exact Active/Retired version + capability and accepts public or private metadata views. A provider-wide capability declaration is checked but not considered authorization. The **executor** must repeat authorization, revocation and exact key-version checks at the point of execution. `EphemeralSignatureKeyOperations` is a concrete local .NET signer, but it retains owned private keys in process memory and provides neither durable versions nor cross-process revocation; it is only an ephemeral/test implementation. Production hardening remains open until a real persistent/HSM executor and .NET NUnit/platform validation are available.

### Phase 18 — ECDH/HKDF boundary

Abstractions hosts `IManagedKeyAgreementBackend`, `IVersionedKeyAgreementOperations`, `IManagedDerivationBackend`, `DerivationContext`, `DerivedKeyLease` and `IDerivedMaterialExportPolicy`. Security hosts `ManagedKeyAgreementBackend`, `EphemeralEcdhKeyOperations` and protected software `DeriveAsync`; registry dispatches by exact stable provider ID. Metadata preflight is not execution authorization; the trusted executor MUST enforce exact-version access again. Only a KDF-derived scoped key returns, never raw ECDH. The default result is not serializable and cannot be read through a property; export is an independently authorized escape hatch. The ephemeral owner provides no durable revocation/MITM resistance.


### Phase 19 — HPKE boundary / no public surface

RFC 9180 remains an opt-in reviewed extension, NOT a composition of existing Phase 18 ECDH derivation and Phase 16 AES-GCM. No `Seal`, `Open`, `SealedPayload`, routing interface or wire layout is published until suite-specific conformance, independently verified provider behavior, authenticated recipient identity and wire/info/AAD review, and trusted exact-version private-key execution can be demonstrated. A reference-only Python test fixture is in `tests/hpke-gate`; see `Laveyana.Security.HpkeGate.md`. This phase is deferred and does not change the public assembly graph.

### Phase 20 — streaming SHA/HMAC boundary

`StreamingLocalCryptography` and internal `StreamHashPump` reside in Security; `StreamProcessingOptions` and optional `IStreamingMacBackend` reside in Abstractions. `SoftwareKeyProviderBackend` initializes `IncrementalHash` from a synchronous protected key lease and releases the lease before async reading. A revision check at EOF invalidates results after concurrent key mutation. `ProviderRegistry` routes streaming MAC by stable `ProviderId` without backend scanning. Segmented AEAD remains unsupported; see `Laveyana.Security.StreamingGate.md`.


### Phase 21 — read-oriented secrets

`ISecretProvider` lives in Abstractions and requires only `FindAsync` (metadata) and `GetAsync` (owned, disposable `SecretReadResult`). `SecretReference` remains `(ProviderId, SecretId)`; no universal `SecretVersion`, implicit secret enumeration or key lifecycle is introduced. `SecretDescriptor.CanOpenMaterial` and `CanExportMaterial` are separate **advertised** capabilities, both false by default; they are not authorization. The provider must enforce its current access policy at `GetAsync` time.

`SecretHandle.UseMaterialAsync` obtains the owned result, validates exact identity and stable provider ID after awaiting, calls a synchronous borrowed-span visitor, and disposes material on success, cancellation or failure. Absence produces `false`, while access denial/provider errors throw. The callback can still intentionally copy borrowed material; no in-process API can technically prevent that. `SecretReadResult` forbids JSON conversion and redacts `ToString`.

`SecretProviderRegistry` provides fixed registration/alias snapshots, case-sensitive aliases and exact-ID lookup; it never scans other providers for an absent secret. `ISecretManagementProvider` is optional and routed only on explicit request, with no implicit write capability. A concrete secret storage provider, cross-process revocation, backend access control and platform testing remain outside Phase 21. All code and NUnit tests remain uncompiled here.



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

## Phase 25 — Diagnostic boundary

The core assembly hosts the optional `Diagnostics.SecurityObservability` backed by
`ActivitySource`/`Meter`/`ILogger`; collectors and durable audit databases are outside
the library dependency graph. It can be used manually without DI. `WithObservability`
only passes the same instance into the software backend and registries. Audit sinks
receive bounded operation/outcome codes, UTC time, and optionally a trace ID, never
sensitive payload or entity identity. Direct custom-provider calls are not implicitly
audited.

## Consolidated enforcement — 21 October 2026

`StoreFilePublication` is the single internal staging path for the ordinary snapshot/bootstrap and experimental rollback journal. It uses the existing pinned Windows handles or Linux descriptors, exclusive temporary creation, exact-byte reread, file flush and native relative rename. Linux additionally fsyncs the pinned directory. Test fault callbacks are per operation/instance, internal, and absent by default; production never reads worker environment settings. Exceptions after native publication starts report an uncertain outcome, including cancellation; cleanup cannot hide the original failure. Temporary cleanup is not a durable recovery decision.

There is **no protected writable FileSystem profile**, authenticated authority binding, enrollment/migration into such a profile, or automatic recovery. `RollbackAuthority` is only a read-only inspection option. It now also rejects either rollback journal entry before consulting the authority, preserving incomplete/ambiguous evidence. Ordinary v1 opens remain experimental and rollback-unprotected; omission of the option is not advertised as safe. `ProvidesRollbackProtection=false` on both platforms.

Managed software AES-GCM now requires a live fresh-material provenance entry from the generating backend instance. A private SHA-256 material fingerprint and exact `KeyReference` select a shared atomic `2^20` invocation budget. Generated candidates cannot reset an existing matching budget. Imported/reopened material is not registered by reads; explicit fresh version creation/rotation establishes a new lifetime. Re-protection alone does not. This intentionally limits forward encryption after backend recreation; historical decryption is unchanged. Fingerprints and budgets are never logged or persisted. The supported lifecycle excludes copying/restoring running process/VM memory and sharing the material with other nonce issuers.

The deterministic issuance implementation is retained as an internal **model-only primitive** for reservation/overflow/cancellation regressions; the policy rejects its selection even with an allocator and a `ProvidesRollbackProtection` bit. `ProviderManaged` never issues a local nonce. Independent authority/provider conformance, downgrade resistance and physical durability remain external gates, not capabilities inferred from interfaces.
