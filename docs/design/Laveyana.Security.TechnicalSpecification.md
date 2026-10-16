# Laveyana.Security — Technical Specification

**English** | [Русский](Laveyana.Security.TechnicalSpecification.ru.md)

> Status: **Generation 1 architecture baseline complete**.
>
> Target framework: `.NET 10` (`net10.0` for cross-platform assemblies).
>
> Package versioning: `X.YYMM.R`.


> **Implementation checkpoint (2026-10-10; Phase 26):** This specification includes normative Generation 1 requirements **and** historical phase-specific implementation notes. Earlier statements such as “not yet implemented” describe the cited phase, not the present source baseline. The current status of each capability is in [README](../../README.md). Source availability is not verified compilation, test execution, security acceptance or a production release. FileSystem is experimental; HPKE and streaming AEAD remain unsupported.

## 1. Purpose

`Laveyana.Security` is the reusable security domain of the Laveyana ecosystem. It provides safe high-level cryptographic operations, key lifecycle management, and secret access while retaining an explicit Advanced/interoperability surface for deliberate low-level use.

The ordinary consumer should configure a safe provider, obtain opaque capabilities, and call operations such as `Encrypt`, `Decrypt`, `Sign`, `Verify`, or `Derive`. Complexity related to lifecycle, routing, storage protection, persistent identity, recovery, and cryptographic policy remains inside the library.

The existing `CryptoKit` is a prototype and a source of reusable ideas, code, and tests. Backward compatibility with its public API is not required.

## 2. Scope

### 2.1. In scope

- secure random generation;
- hashing and fixed-time comparison;
- HMAC;
- HKDF and password-based KDF primitive support;
- authenticated symmetric encryption/decryption;
- asymmetric signing/verification;
- key agreement followed by KDF;
- conditional `Seal/Open` after a dedicated HPKE design/security gate;
- key identities, descriptors, typed capabilities, versions, rotation, retirement, and deletion;
- software, OS-backed, HSM, remote, and non-exportable providers;
- software storage contracts and a standard protected FileSystem store;
- safe temporary access to secret/key material;
- versioned cryptographic payloads and persistent metadata;
- safe streaming primitives after a dedicated streaming-protocol gate;
- logging/metrics/tracing/audit hooks without sensitive-data leakage.

### 2.2. Out of scope

- authentication, authorization, JWT, user management;
- password login/reset workflows and credential databases;
- TLS/transport-security replacement;
- database-specific encryption policy or deciding which application data to encrypt;
- certificate/X.509 management in Generation 1;
- generic plugin scanning;
- global event bus;
- hidden background runtime;
- custom ad-hoc HPKE-like or streaming encryption protocols.

Application/domain workflows belong to integration layers such as `Laveyana.Persistence.Security`.

## 3. Repository and assemblies

Required baseline:

```text
Laveyana.Security/
├── src/
│   ├── Laveyana.Security.Abstractions/
│   ├── Laveyana.Security/
│   ├── Laveyana.Security.FileSystem/
│   └── Laveyana.Security.DependencyInjection/
├── tests/
│   ├── Laveyana.Security.Tests/
│   └── Laveyana.Security.IntegrationTests/
└── docs/
```

Responsibilities:

| Assembly | Responsibility |
|---|---|
| `Laveyana.Security.Abstractions` | Stable consumer contracts, identifiers/value objects, result types, and real cross-assembly extension boundaries. |
| `Laveyana.Security` | Domain rules, orchestration, standard concrete crypto implementations, validators, codecs, locking/workflow mechanics, Advanced implementation surface. |
| `Laveyana.Security.FileSystem` | Standard software `IKeyStore` implementation with protected persistence, recovery, and filesystem safety. |
| `Laveyana.Security.DependencyInjection` | `IServiceCollection` composition, method-based configuration DSL, validation, lifetimes, optional hosted integration. |
| Platform/provider package | Added only for a real platform/dependency/provider boundary. |

`Laveyana.Security.Abstractions` is the stable bottom layer and never depends on concrete Security/FileSystem/platform assemblies.

## 4. Inherited engineering requirements

Mandatory shared requirements: consistent `Laveyana.*` names, .NET 10, controlled dependencies, release and documentation lifecycle; readable file-scoped C#, nullable/analyzers/XML docs, English-only source comments, correct async/cancellation and ownership, explicit AOT/trimming guarantees, and safe observability. The full rules are included directly in the standalone library implementation master prompt.

Security-specific strengthening: no default sensitive-material exposure, no unsafe algorithm/configuration fallback, and no claim of persistent or cryptographic rollback protection without an independently verifiable capability.

## 5. Public API model

The public surface is split by semantics, not by unnecessary packages.

### High-Level API

Must provide:

- safe defaults;
- minimal cryptographic parameter selection;
- opaque key/secret capabilities;
- immutable self-describing managed result values;
- no manual nonce/tag management for ordinary consumers;
- fail-closed behavior when a required security capability is unavailable.

### Advanced API

Used intentionally for:

- raw/interoperability primitives;
- explicit import/export;
- explicit material leases;
- algorithm/parameter selection;
- destructive lifecycle operations;
- protocol-level integrations.

## 6. Algorithm policy

Generation 1 high-level defaults:

| Capability | Default |
|---|---|
| Random | `RandomNumberGenerator` |
| Hash | SHA-256 |
| MAC | HMAC-SHA-256 |
| Authenticated encryption | AES-256-GCM |
| General KDF | HKDF-SHA-256 |
| Password KDF primitive | PBKDF2-HMAC-SHA-256 with explicit work factor/policy version |
| Signature | ECDSA P-256 + SHA-256 |
| Signature alternative | RSA-PSS; new RSA keys >= 3072 bit |
| Key agreement | ECDH P-256 followed by KDF |

Supported hash/MAC alternatives are SHA/HMAC SHA-384 and SHA-512. ChaCha20-Poly1305 is allowed only after runtime/platform capability is confirmed.

Algorithm catalog states:

```text
Recommended
Supported
LegacyReadOnly
```

No silent downgrade is allowed. If an explicitly required/preferred algorithm is unavailable, validation/configuration/operation fails.

PQC must be addable later without redesigning `KeyId`, lifecycle, or provider boundaries, but is not a Generation 1 default.

## 7. Key identity and capabilities

Three identities are distinct:

```text
KeyName    → consumer/application alias
KeyId      → immutable cryptographic-generation identity
KeyVersion → exact material-version identity within one KeyId
```

Persistent managed reference:

```text
KeyReference = ProviderId + KeyId + KeyVersion
```

`KeyName` and `ProviderAlias` are not persistent cryptographic identity.

`KeyVersion` allocation is irreversible inside the current authoritative history. Deleted/discarded version numbers are not reused; gaps are valid. Cross-snapshot monotonicity is not promised for rollback-unprotected external restores.

Logical and exact handles are different concepts:

```text
logical capability   = ProviderId + KeyId
exact-version handle = ProviderId + KeyId + KeyVersion
```

Logical capabilities resolve current `Active` before each forward operation. Exact handles never move automatically.

Typed capability views include:

```text
EncryptionKey
MacKey
DerivationKey
AsymmetricPublicKey
AsymmetricPrivateKey
```

The algorithm is exact-version metadata, not the key type itself.


### 7.1. Canonical Generation 1 identity text

- `ProviderId`, `KeyId` and `SecretId` are nonempty UUIDs with exact lowercase `8-4-4-4-12` (`D`) text, for example `12345678-1234-4234-8234-123456789abc`. A default value struct is invalid. A newly provisioned `ProviderId` must be persisted and reused after restart, not regenerated on each startup.
- `KeyVersion` is a positive `Int64` represented by invariant decimal digits without signs or leading zeros. Allocation and the high-water mark remain responsibilities of authoritative lifecycle/store logic.
- `KeyReference` = `provider-uuid/key-uuid/version`; `SecretReference` = `provider-uuid/secret-uuid`. Runtime aliases, CLR names and accidental enum ordinals are forbidden in exact references.
- `ProviderAlias` and `KeyName` are case-sensitive ordinal ASCII names of 1–128 characters, starting with a letter and then using letters, digits, `.`, `_` or `-`; no trimming, case folding or path interpretation. Neither may replace persistent identity.
- `AlgorithmId` and `CapabilityId` use 1–128-character lowercase ASCII tokens starting with a letter; digits and single internal `.`, `_`, `-` separators are allowed. A token identifies an algorithm/capability but alone asserts no availability, permission or cryptographic strength.
- These value objects **explicitly** define their `ToString`/`Parse` conversions as canonical text. Future metadata/envelope codecs must separately define format versions and stable state/variant names. CLR enum values/declaration order and reflection names must never become accidental persisted contracts.
- `KeyDescriptor`, `KeyVersionDescriptor` and `SecretDescriptor` are immutable metadata snapshots, not I/O or authorization/lifetime handles. An `Active` logical descriptor includes an active version; `Retired`/`Deleted` do not. Version capabilities are defensively copied and ordinally sorted; their presence does not bypass policy/provider checks.

## 8. Key lifecycle

Logical states:

```text
Active
Retired
Deleted
```

Version states:

```text
Pending
Active
Retired
Deleted
```

`Discarded` is not a public state. Discarding a never-activated `Pending` version destroys material and transitions it to `Deleted`, while its `KeyVersion` remains permanently reserved within the authoritative history.

Stable invariants:

- logical `Active` has exactly one Active version;
- the default lifecycle has at most one Pending version;
- logical `Retired` has no Active or Pending version;
- current Active version cannot be removed through normal `DeleteVersion` or `ForceDeleteVersion`;
- normal destructive path is `Active → Retired → Deleted`;
- `KeyName` is released only after durable completion of `DeleteKey`;
- a retired logical generation is not reactivated in Generation 1.

Activation replacement is one atomic/recoverable domain transition: previous Active → Retired and target Pending → Active.

## 9. Create/Get/Find/GetOrCreate and concurrency

- `Create`: create a new logical generation and initial Active version; occupied name → conflict.
- `Get`: existence expected; absence → exception.
- `Find`: absence is a normal outcome.
- `GetOrCreate`: return existing or atomically create a new logical generation.

Generation 1 name scope:

```text
(ProviderId, KeyName) → KeyId
```

Correct concurrent `GetOrCreate` requires two layers:

1. local per-name keyed lock to reduce redundant work;
2. store-level atomic claim/create of the unique name binding and aggregate as the final coordination point across instances/processes.

`Find → Create` alone is never treated as atomic.

### 9.1. Management operations and deletion safety

- Rotation supports immediate operation and staged `CreateVersion(Pending) → Activate`, with atomic version replacement. `Retired` retains material for allowed historical decrypt/verify and is distinct from `Deleted`.
- `DeleteKey` performs a recoverable cascade only after checking all version states and retention. `Deletable` does not prove the application has no historical references.
- Explicit Advanced `ForceDeleteKey`/`ForceDeleteVersion` are destructive; separately deleting the current `Active` version remains forbidden. `ForceDeleteKey` removes the aggregate coherently but may make historical data inaccessible.
- Concurrent transitions use expected revisions / conditional replacements. Retrying non-idempotent operations must not be unbounded or implicit.

## 10. Provider architecture

Every persistent provider has a stable immutable `ProviderId`. `ProviderAlias` is a runtime/configuration convenience that resolves to a single `ProviderId` inside an immutable composition snapshot.

Rules:

- `ProviderId` unique;
- `ProviderAlias` unique;
- duplicate registration fails startup/configuration;
- exact reference routing uses `ProviderId` directly;
- no scan-all-providers lookup;
- alias remapping never changes persisted reference meaning.

Backend boundary:

```text
High-Level Security
        ↓
Crypto / Key Orchestration
        ↓
IKeyProviderBackend
├── Software
├── OS-backed
├── HSM
└── Remote/custom
```

Capabilities are granular. An operation is allowed only when both key policy and provider capability permit it.

Provider migration creates a **new** ProviderId/KeyId generation; existing KeyId is never moved between providers and no redirect registry changes old references.

## 11. Software storage and protection

`IKeyStore` belongs to `Laveyana.Security.Abstractions`. It provides persistence/consistency primitives for software-managed providers, not lifecycle policy.

Conceptual responsibilities:

- find/load;
- atomic name claim/create;
- conditional replace with expected revision;
- delete;
- material read/write/destroy;
- capability declaration.

AEAD deterministic nonce allocation is **not** mandatory `IKeyStore` behavior.

`IKeyStoreProtector` is also an Abstractions extension boundary and exists before concrete FileSystem implementation. It must keep its root protection secret opaque and provide stable/versioned `ProtectorReference` plus domain-separated purposes at least for `Metadata` and `KeyMaterial`.

The standard FileSystem store has no secure-default raw-material persistence path and no plaintext fallback.

## 12. FileSystem and rollback model

The standard FileSystem store:

- creates/validates an isolated root;
- verifies ACL/Unix permissions and ownership assumptions;
- rejects unsafe symlink/reparse redirection;
- stores protected metadata/material envelopes;
- uses atomic/conditional write patterns and recoverable temp/journal/checkpoint workflows;
- fails closed on corrupted/tampered protected state;
- does not claim forensic secure erase;
- declares `ProvidesRollbackProtection = false` unless an independent rollback-resistant authority exists.

Unix baseline: directory `0700`, secret file `0600` or stricter. Windows uses ACL/ownership validation and post-configuration verification.

Crash recovery and external rollback are separate classes:

- **CrashRecovery:** interrupted operation inside current authoritative history; journal/temp/checkpoint may resume or roll back the incomplete operation.
- **ExternalRollback/Restore:** a valid current store is replaced by an older but still authentic snapshot; a rollback-unprotected store may be unable to detect this.

A known restore requires explicit reconciliation before unsafe forward operations. Safe default: old restored generation becomes historical/read-only where possible; new forward use creates a new `KeyId` with fresh material.

## 13. AEAD nonce policy

Ordinary consumers never supply nonces in the high-level API.

Managed AES-GCM supports three strategies:

```text
Randomized
RollbackProtectedDeterministic
ProviderManaged
```

### Randomized

- 96-bit nonce from CSPRNG;
- default for rollback-unprotected software storage;
- probabilistic uniqueness;
- CSPRNG state must not be the rollback-able FileSystem counter state;
- invocation/data bounds are enforced and exhaustion fails closed/re-keys.

### RollbackProtectedDeterministic

Allowed only with:

```text
ProvidesRollbackProtection = true
+
IAeadNonceStateStore (or equivalent)
```

State is bound to exact `KeyReference`. Reserved but unused values after a crash are burned and never reissued.

### ProviderManaged

Provider owns AEAD execution and safe nonce lifecycle and returns required public operation metadata.

Deterministic allocation on the default rollback-unprotected FileSystem is forbidden.

Imported AES raw material with unknown prior nonce history cannot enter ordinary managed forward encryption without an explicit safe policy/provider mechanism.

## 14. Payloads, formats, AAD, and outcomes

Managed results are self-describing immutable values:

```text
EncryptedPayload  → exact KeyReference + algorithm/public parameters + nonce + ciphertext + tag + format version
SignaturePayload  → exact KeyReference + signature scheme/public parameters + format version
MacResult         → exact KeyReference + algorithm/public parameters + format version
```

Security-critical encrypted-payload metadata is cryptographically bound as internal authenticated metadata.

Optional application AAD is external input: authenticated, not encrypted, and not persisted automatically in the payload.

Persistent/runtime versions are independent:

```text
LibraryVersion
MetadataFormatVersion
ProtectedMaterialEnvelopeVersion
EncryptedPayloadFormatVersion
StreamingFormatVersion
```

Runtime/domain objects are not permanent persistence schemas. Unknown newer formats fail closed.

Invalid signature/MAC is a normal negative result. `TryDecrypt` only normalizes authentication failure; provider/configuration/format/cancellation/programming failures remain visible.

### Phase 15 concrete managed payload contract (provisional)

`Laveyana.Security.Abstractions.Payloads` owns copy-on-input immutable result types. `EncryptedPayload` stores exact `KeyReference`, algorithm, 12-byte AEAD nonce, 16-byte authentication tag and 0–16 MiB ciphertext; `DetachedEncryptedPayload` stores the same critical metadata plus committed ciphertext length while ciphertext travels separately. Algorithms are limited to AES-256-GCM and ChaCha20-Poly1305 representations (availability is provider-controlled). `SignaturePayload` supports ECDSA-P256-SHA256 IEEE P1363 64-byte and RSA-PSS-SHA256 raw 256–1024-byte signature representations. `MacResult` accepts full-length HMAC-SHA256/384/512 only; legacy HMAC-SHA1 and truncated tags are excluded from default result values. All buffers are copied in and exported only through copy methods; construction does not assert an authentic signature/MAC/tag.

Canonical little-endian records use four-byte markers `LEP1`, `LDP1`, `LSP1`, `LMR1`, `UInt16 version=1`, `UInt16 flags=0`, strict UTF-8 `UInt16`-length identity/algorithm tokens, then bounded `UInt32`-length byte fields. Signatures additionally include an explicit, algorithm-checked encoding token; detached results include a fixed ciphertext-length field. Readers reject unknown versions, flags, invalid/duplicate identity fields, noncanonical identities, trailing bytes and bounds violations. Records have an upper limit of 16 MiB + 4 KiB.

`EncryptedPayloadAssociatedData.Build` constructs domain-separated `Laveyana.Security/managed-aead/v1` AAD over exact KeyReference, algorithm, 12-byte nonce, tag length, ciphertext length and a length-delimited *caller-provided* application AAD (maximum 64 KiB). External AAD is **never serialized** with a payload and must be provided identically during decryption. Both AEAD encrypt and decrypt MUST use this exact sequence; otherwise payload metadata is not authenticated. The codec alone provides no authenticity, no key lookup, no cryptographic execution and no automatic rotation handling. Phase 16 binds the selected Active version to an authenticated exact reference for AES-GCM; Phase 17 implements managed HMAC and optional versioned signing adapters, pending verified build/tests. The new wire formats are provisional until executable compatibility tests run in .NET 10.

## 15. Secrets and sensitive material

Secrets use a read-oriented model:

```text
SecretId
SecretReference = ProviderId + SecretId
SecretDescriptor
SecretHandle
ISecretProvider
```

The base secret provider requires only `Get/Find`; management is an optional separate capability.

Default access does not expose long-lived `string`/`byte[]` values. Controlled access uses:

- scoped callback access;
- disposable `SensitiveMaterialLease` over owned mutable memory.

A lease zeroizes only the memory it owns and does not promise erasure of unrelated managed/native/OS copies.

`CanOpenMaterial` and `CanExportMaterial` are separate capabilities.

### 15.1. Import/export and representations

- Advanced import explicitly specifies provider, key kind/algorithm/capabilities, exportability and ownership. The library does not wipe caller-owned input by default; ownership transfer requires a distinct explicit contract.
- `CanOpenMaterial` is not `CanExportMaterial`; non-exportable providers need not materialize private bytes in-process.
- Standard public asymmetric export uses `SubjectPublicKeyInfo`; private import/export uses `PKCS#8` only when policy permits. Avoid proprietary private key formats.
- Key agreement passes the shared secret through a KDF with a canonical domain-separated context and does not return raw shared secrets by default. Encrypted streaming remains gated; streaming hash/MAC may be delivered independently.

## 16. DI, async, time, and observability

Core remains usable without DI.

`Laveyana.Security.DependencyInjection` provides method-based configuration:

```csharp
services.AddSecurity(settings =>
{
    settings
        .Use...
        .Enable...
        .With...;
});
```

`AddSecurityDefaults()` is a preset over the same composition model. It requires an already selected safe protector, never performs hidden assembly scanning/platform guessing, has no plaintext fallback, and fails fast for invalid composition. Platform packages may provide platform-safe presets such as `AddSecurityWindowsDefaults()`.

Pure local CPU primitives may be synchronous. Provider/storage/lifecycle I/O is asynchronous. Fake async is forbidden. `CancellationToken` is last where the operation is genuinely cancellable. Cancellation after durable commit does not roll back the committed effect.

Shared/DI services are thread-safe; narrow per-key/per-name synchronization is preferred. Time-dependent policy uses `TimeProvider`.

Observability uses standard .NET logging/metrics/tracing. Sensitive payload/material is never logged. High-cardinality `KeyId`/`KeyName`/`SecretId` are not default metric labels. Core may emit audit events but does not own durable audit persistence.

## 17. Releases and documentation

- Release version follows the ecosystem contract `X.YYMM.R` (`R` is a stable release sequence within `(X, YYMM)`, starting at `0`) with SemVer-compatible prerelease suffixes. The former `X.YY.MM.DD` is obsolete.
- .NET package, persistent metadata, protected envelope, encrypted payload, and stream format have independent version identities.
- Design documents remain equivalent EN/RU pairs: `TechnicalSpecification`, `Architecture`, `DecisionLog`, `Roadmap`. Do not create pre-implementation README, CHANGELOG, or placeholder LICENSE. Follow the lifecycle requirements in the standalone library master prompt once real code and public releases exist.
- Support generations, the API compatibility gate, and deprecation follow the standalone master prompt; unsafe security APIs may require justified accelerated removal.

## 18. Testing and architecture gate

Required test categories include:

- happy path and expected negatives;
- invalid configuration and dependency failure;
- cancellation and idempotency;
- concurrency and cross-process coordination;
- migrations/recovery/failure injection;
- corruption/tampering/unknown future formats;
- provider capability mismatch;
- filesystem permissions and symlink/reparse attacks;
- randomized and deterministic AEAD nonce semantics;
- imported-key unknown nonce-history rejection;
- external rollback/restore reconciliation;
- known-answer crypto vectors;
- codec/parser fuzzing.

Architecture stage is complete because purpose/scope, dependency boundaries, public/extensibility surfaces, identity/lifecycle, provider/store/protector boundaries, AEAD nonce policy, persistence/recovery, DI/defaults, versioning/support, testing, and security gates are fixed.

No previously recorded architectural DXX item blocks Phase 1; any new implementation evidence must be evaluated before reopening a decision. Concrete method signatures, exact stable identifier encodings, serializer choice, internal type/folder names, and the exact platform-protector mechanics remain implementation-level choices as long as they preserve the frozen invariants.

## 19. Normative references and evidence threshold

- AEAD/nonce design: RFC 5116 and the applicable NIST SP 800-38D edition (recheck before release).
- Optional HPKE `Seal/Open`: RFC 9180 with selected suites, reviewed implementation, interoperability vectors and dedicated security review.
- Streaming AEAD: an analyzed standardized/reviewed construction (such as the Google Tink Streaming AEAD model) and an explicit protocol/security gate.
- A standard is a review baseline, not proof that an arbitrary implementation is secure.

## 20. Generation 1 release acceptance summary

Generation 1 may be released only when the implementation demonstrates all of the following:

- ordinary encryption/signing/MAC/KDF usage does not require dangerous parameter management;
- default APIs do not expose raw key/secret material;
- software, OS-backed, HSM, remote, and non-exportable providers fit one capability model;
- `KeyReference` is stable and historical operations remain valid after rotation;
- concurrent `GetOrCreate` cannot produce two winners for one provider/name;
- lifecycle rejects unsafe transitions and never reuses discarded/deleted KeyVersion identities inside authoritative history;
- FileSystem fails closed on unsafe permissions and never stores raw material as a secure default;
- security-critical metadata has integrity protection, while integrity is not misrepresented as rollback protection;
- protector re-protection is distinct from cryptographic key rotation;
- persistent formats evolve independently and reject unknown newer versions;
- cancellation semantics do not imply rollback after durable commit;
- secrets do not become indefinite strings/byte arrays by default;
- observability does not leak sensitive payload/material;
- default configuration performs no silent algorithm/security downgrade;
- managed AES-GCM has explicit capability-driven nonce allocation;
- known external rollback of rollback-unprotected state requires reconciliation before unsafe forward use;
- HPKE and encrypted streaming are either passed through their required security gates or explicitly remain unsupported/deferred;
- implementation, integration, concurrency, corruption, recovery, permission, negative-crypto, and fuzz tests pass;
- final EN/RU documentation matches the implemented public API and lifecycle.

## 6.1 Phase 3 — local primitive implementation boundaries

The Phase 3 implementation in `Laveyana.Security` (`Algorithms` and `Primitives`) provides:

- `AlgorithmPolicy`: explicitly classified known `AlgorithmId` values (`Recommended`, `Supported`, `LegacyReadOnly`), purpose checks, unknown-ID rejection and no silent downgrade. AES-GCM and ChaCha20-Poly1305 availability is gated by the .NET `.IsSupported` checks. Catalog membership does not mean a provider/key supports the algorithm, or that managed encryption/signature APIs are implemented yet.
- `LocalCryptography`: secure RNG, SHA-256, HMAC-SHA-256 (new keys at least 32 bytes), fixed-time comparison, HKDF-SHA-256 (nonempty domain-specific info, salt at least 16 bytes), PBKDF2-HMAC-SHA-256 (salt at least 16 bytes, versioned work factor and 16–1024 output bytes).
- `AdvancedLocalPrimitives`: explicit SHA-256/384/512 and HMAC-SHA-256/384/512, RFC 5869 HKDF including optional empty salt/info, and explicit historical PBKDF2 or SHA-1/HMAC-SHA-1 processing with `AlgorithmUse.HistoricalVerification`. Legacy operations cannot create new protected data.
- `Pbkdf2WorkFactor`: Generation 1 policy version 1, **600,000** default/minimum and **10,000,000** maximum iterations for new derivations. Persist policy version, actual iteration count, salt and derived length as needed for reproducible verification. Older work factors are accepted only by the explicitly named historical derivation API. Future policy versions may use different parameters.

Security caveats: fixed-time comparison reveals unequal input lengths. HKDF does not increase entropy. PBKDF2 is a primitive, not a complete password-verifier or authentication system. Raw span/array inputs and outputs of primitive APIs remain caller-owned unless explicitly put into a Phase 4 lease. Password bytes have explicit caller-selected encoding and normalization. Do not treat this phase as a managed encryption service.

Reference vectors: [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231), [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), standard SHA-2 vectors and known PBKDF2-HMAC-SHA-256 vectors. Phase 3 cannot be accepted until compilation and NUnit tests run under .NET 10.

## 6.2 Phase 4 — sensitive memory implementation boundaries

`Laveyana.Security.Abstractions.Sensitive` provides `SensitiveMaterialLease` (one mutable, privately owned byte-array, 1–1,048,576 bytes) and `SensitiveMaterialScope` for synchronous scoped visitors. `CreateCopy` performs one private copy and leaves external bytes untouched; `TakeOwnership(byte[])` transfers **logical** ownership without copying and requires the caller to abandon existing aliases after success. Failure before transfer leaves ownership with caller. Both scoped helpers dispose in a `finally`-equivalent `using` path, including callback exceptions.

`UseMaterial` accepts a synchronous delegate with `ReadOnlySpan<byte>`; no public secret getter, implicit conversion to `byte[]`, `Task`-returning visitor or implicit export exists. Callback execution happens outside internal locks. Concurrent readers may finish after `Dispose` begins; disposal then rejects new access and zeroizes the owned buffer after the last reader exits. Repeated `Dispose` is safe. The lease redacts `ToString()` and rejects built-in `System.Text.Json` serialization/deserialization. The library cannot prevent explicit copies by user callbacks, reflection-based third-party serializers/loggers or OS/runtime duplicates. It never wipes caller-owned sources, except when the caller explicitly transfers the same array. Timely zeroization requires disposal; no finalizer guarantee or enforced visitor timeout is advertised.

**Verification gate:** compile the six projects on .NET 10 and execute NUnit tests, including disposal, exception, aliasing, concurrent reader/dispose, serialization and validation cases. Static structural checks alone do not close Phase 4.

## 6.3 Phase 5 — logical/exact handles and capability metadata preflight

`Laveyana.Security.Abstractions.Handles` provides immutable `LogicalKeyHandle` (`ProviderId + KeyId`) and `ExactKeyHandle` (`KeyReference`). An exact handle is pinned to one version; a logical handle never stores Active-version state. Both reject default/undefined identities at construction and redact their ordinary `ToString()` output. The explicit `KeyReference` remains available for correctly persisted historical references.

`Laveyana.Security.Abstractions.Capabilities` provides `EncryptionKey`, `MacKey`, `DerivationKey`, `AsymmetricPublicKey`, and `AsymmetricPrivateKey` typed metadata views. A view binds only a logical identity and `IKeyMetadataResolver`; each forward resolve reads a fresh logical snapshot, checks that it is Active, then validates the matching exact-version state, key kind and declared operation capability. A historical resolve takes an exact handle belonging to the same logical identity, never substitutes another version, rejects Pending/Deleted versions and Deleted logical keys, and permits Active/Retired exact versions only under consistent metadata. Missing/mismatched snapshots or capability/kind violations fail closed.

**Security boundary:** `KeyCapabilityResolution` is **metadata-only preflight, not authorization, not a lease, not a reservation and not a cryptographic operation**. `KeyVersionDescriptor.Capabilities` expresses declarations only. Neither a metadata check nor an `IKeyMetadataResolver` query can safely authorize a future operation across rotation, revocation, policy changes or backend concurrency. Future provider dispatch MUST independently and atomically (where required) enforce key policy, provider capability, actual lifecycle state, and algorithm policy against the exact material it uses. A preflight result may become stale immediately. Provider-backed cryptography and persistent lifecycle remain outside Phase 5.

**Verification gate:** compile .NET 10 and execute unit tests for rotation, pinned historical references, capability and kind mismatches, inconsistent snapshots, cancellation and lifecycle states. Static structural checks alone do not close Phase 5.

## 6.4 Phase 6 — pure lifecycle planner implementation boundaries

`Laveyana.Security.Lifecycle` is **internal to core Security** for Generation 1; it has no public provider contract yet. `KeyLifecycleSnapshot` validates stable identity, the logical/version state relationship (one Active iff logical Active, at most one Pending, no Pending while Retired/Deleted), and a bounded immutable, sorted version history. `HighWaterMark` is separate from entries and survives discarded/deleted identities and tombstone compaction. An attempt to allocate after `long.MaxValue` is explicitly rejected.

Pure `KeyLifecyclePlanner` methods return immutable `KeyLifecycleTransition` plans: `Create` starts at Active v1; `CreatePendingVersion` reserves Pending; `Activate` replaces old Active → Retired and target Pending → Active atomically in a single plan; `Rotate` performs immediate replacement with a new version; `RetireKey` refuses unresolved Pending and forever ends forward use; `DiscardPending` creates a Deleted tombstone. `DeleteVersion` only permits Retired versions and checks retention; `ForceDeleteVersion` permits Retired/Pending but *never* current Active. `DeleteKey` requires Retired and checks all surviving retention constraints; `ForceDeleteKey` atomically plans a destructive cascade to Deleted, even if Active. No transition may reactivate Retired or Deleted logical keys.

Each version has a deletion deadline and optional hold. Normal deletion requires an explicit, defined UTC timestamp; no ambient clock or I/O is used. Force operations explicitly bypass retention and can destroy historical decrypt/verify ability. Plans classify `Applied` vs. `AlreadyApplied`; CreatePendingVersion/Rotate are non-idempotent. Even a repeated operation with an `AlreadyApplied` outcome is **not** evidence of an earlier durable commit: the authoritative store must check revisions, coordinate claims and material effects, and resolve ambiguous commits before retrying. `KeyName` release happens only after the durable DeleteKey/ForceDeleteKey commit in a later phase. High-water monotonicity only holds inside the represented/authoritative history, not across an undetected rollback of a rollback-unprotected store.

**Verification gate:** .NET 10 build and real NUnit tests for transition matrix, active invariant, version monotonicity and exhaustion, pending/discard/activation, retention and force deletion, idempotent no-ops, snapshot immutability and randomized sequences. Static validation cannot close this gate.

## 6.5 Phase 7 — provider contracts and exact routing

The external `IKeyProviderBackend` is defined in `Laveyana.Security.Abstractions.Providers` and extends `IKeyMetadataResolver`. It exposes only an immutable stable `ProviderId`, exact logical/version metadata reads, and `GetCapabilitiesAsync` returning an immutable `ProviderCapabilitySnapshot` (at most 64 distinct `CapabilityId` entries). These are provider-wide declarations only: actual dispatch must independently validate per-key capability, policy, lifecycle and algorithm. Discovery is not an authorization grant; there are no cryptographic operations or material exports in this contract yet.

Core `ProviderRegistry` accepts a complete set of `ProviderRegistration` at startup (0–1024 providers) and captures it in private mappings. It rejects duplicate `ProviderId`/`ProviderAlias`, undefined identities, null registrations and changing backend identities. Aliases are ordinal, case-sensitive and used only for explicit `ResolveAlias`; they never redirect a persisted reference. `GetRequired`, `Route`, `FindLogicalAsync` and `FindExactAsync` dispatch **only by ProviderId**, with no fallback or scanning other providers.

The registry validates logical/exact metadata and capability-snapshot identity as well as backend identity before and after awaited calls. Mismatches fail closed; an absent key from its exact provider returns null. Cancellation is passed through and checked both before and after awaited calls. Immutable composition freezes membership and aliases, not the availability/capabilities of mutable or remote backends. A capability declaration can immediately become stale. Phase 7 contains no `IKeyStore`, persistence, software adapter, DI registration, or atomic cryptographic execution. Gate: compile on .NET 10 and run NUnit for duplicates, undefined identity, invalid responses, capability checks, cancellation, alias remapping and no scan-all-provider routing.

## 6.6 Phase 8 — software storage and at-rest protection contracts

`IKeyStore`, `IKeyStoreProtector`, and optional `IRollbackProtectedNonceAllocator` are public extension points in Abstractions only. Storage implementations must expose `KeyStoreCapabilities.ProvidesRollbackProtection` truthfully and guarantee cross-process, durable atomic name creation; CAS replacement of metadata and version-scoped protected material changes; and aggregate deletion that atomically removes all material plus the name claim. A rejected write is effect-free. `TryCreateAsync` requires one initial Active v1 protected material and produces revision **1**, `TryReplaceAsync` requires an expected revision and produces the next strictly sequential positive revision, while a successful delete has no surviving revision. Overflow must fail closed. A previously used `(ProviderId, KeyId)` remains reserved in the same authoritative history even after deletion; reusing names after committed deletion is permitted. `ReadMaterialAsync` checks an expected aggregate revision atomically. Stores handle no plaintext or lifecycle policy.

`ProtectedStoreEnvelope` copies opaque ciphertext bytes defensively (1–2,097,152 bytes), labels them with stable versioned `ProtectorReference` and declared `ProtectionPurpose`, and **does not authenticate or encrypt** on its own. Implementers of `IKeyStoreProtector` MUST cryptographically authenticate the supplied context, immutable protector identity/generation and purpose with authenticated encryption. Missing/wrong/modified binding or unsupported generation is a terminal failure; there is no plaintext fallback. `KeyStoreProtectionContext` generates distinct canonical v1 AAD for metadata `(ProviderId, KeyId, committed revision)` and material `(ProviderId, KeyId, KeyVersion)`. Protector implementations must prevent authenticated-context mutation during asynchronous use and must not retain borrowed sensitive spans. The protector's root secret remains opaque; returned plaintext is a caller-disposed `SensitiveMaterialLease`. Historical protector generations require explicit decrypt support, not silent upgrades.

Deterministic 96-bit nonce allocation requires a separately implemented `IRollbackProtectedNonceAllocator` that reserves non-overlapping, durable `(Prefix32, Counter64)` ranges for an exact `KeyReference`. It must never reissue ranges following crashes, restores or counter-state reinitialization; committed but unused ranges are burned. The interface is optional and is not part of `IKeyStore`; claiming rollback protection without an independent authority is prohibited. Filesystem-only storage uses the later randomized AES-GCM policy instead. External rollback of an authenticated old snapshot remains undetectable without an independent trust anchor.

The test-only `MemoryStore` exercises conflicting concurrent claims, same-revision CAS races, material changes, read revision mismatch, deletion/name release and cancellation-before-commit. It is **not** a production in-memory store or an assurance of cross-process durability. **Phase 8 verification gate**: compile on .NET 10; execute all NUnit tests; independently compile an Abstractions-only external store/protector; and later run actual multi-process crash/recovery tests against the concrete store. Static source checks alone do not pass the gate.

## 6.7 Phase 9 — operational software provider boundaries

The concrete `SoftwareKeyProviderBackend` is a store/protector adapter, **not** a complete cryptographic provider. Its public API implements Create, Get (FindLogical), Find (FindByName/FindExact), GetOrCreate, CreateVersion, Activate, Rotate, Retire, Discard, DeleteVersion, ForceDeleteVersion, Delete and ForceDelete. A `SoftwareKeyRetention` record supplies per-version UTC deadline and indefinite hold when creating/rotating. Supported new-generation profiles are symmetric AES-256-GCM, runtime-available ChaCha20-Poly1305, HMAC-SHA-256/384/512, and HKDF-SHA-256 with a fresh 32-byte CSPRNG key. No import, material export, ECDSA/RSA private-key lifecycle or actual AEAD/MAC/KDF operation is implemented yet.

All lifecycle effects are produced by the Phase 6 planner against authenticated committed metadata, then committed with Phase 8 CAS under the exact expected revision. Create has revision 1; replace deterministically uses `expected + 1`, never another allocator scheme. The provisional metadata codec `LSM1` strictly bounds size (1 MiB), version count (2048) and capabilities (64), checks embedded identities and tombstone/high-water invariants, and zeroizes intermediate byte arrays where feasible. It needs Phase 11 schema/migration tests before release. Protected material is upserted only for new versions and removed with Discard/DeleteVersion/ForceDeleteVersion; deletion cascades through the store. Invalid unknown/cross-provider references fail closed. `FindExact` demands revision-consistent protected material for non-deleted versions.

No automatic retries follow definitive CAS conflicts or uncertain commits. Throw `SoftwareKeyCommitUncertainException` if a mutating store call throws after invocation, because it might have committed; check authoritative state and explicit application idempotency before issuing a new non-idempotent command. `GetOrCreate` may read the name winner only after a definitive `NameTaken` rejection and must verify the complete requested profile. Store and protector **must** satisfy contracts, while fake implementations prove only in-process behavior. `GetCapabilitiesAsync` advertises an empty set until real executable cryptographic operations are available. Gate remains open without a real .NET build and NUnit run, and without durable cross-process store integration.

## 6.8 Phase 10 — AEAD nonce implementation boundaries

Phase 10 adds internal AES-256-GCM nonce policy bound to an exact `KeyReference`, without expanding the mandatory public provider/store contract. The selection uses trusted dispatch-origin material provenance, restore status, provider guarantees, and independently verified rollback-resistant nonce authority.

1. With no allocator, freshly generated material gets 96-bit randomized CSPRNG nonces, capped at 2²⁰ issuances per exact key **within one process**. This quota cannot globally enforce a key lifetime across processes, restarts or restores; future orchestration must establish cumulative limits. Random nonces only provide probabilistic uniqueness.
2. Deterministic issuance requires `ProvidesRollbackProtection=true` **and** `IRollbackProtectedNonceAllocator`. Each durable reservation covers 64 counters; unused committed counters are burned. A wrong reference, duplicate/reordered local range or a reservation whose commit is uncertain fails closed without a fallback. Cross-process and restore durability is a verified external allocator obligation; ordinary store counters are not acceptable.
3. Provider-managed issuance never returns a local nonce; it requires a verified provider that itself executes AEAD with a safe nonce lifecycle. Imported material with unknown previous nonce use requires an additional trustworthy history-isolation guarantee.
4. A known externally restored old key generation is ineligible for forward encryption until explicit reconciliation/re-key with a **new KeyId**. Existing sessions must be invalidated when a restore is discovered; Phase 10 does not discover restores automatically. Unknown-history imports cannot use ordinary managed forward encryption.
5. Managed whole-buffer preparation accepts 0–64 MiB per message and validates bounds before issuing nonces. Issuance never establishes authorization, Active state, exact material identity or successful encryption.

**Verification gate:** .NET 10 build/NUnit, concurrency, simulated restore with an independent fake authority, UInt64 boundary handling, malformed reservations, ambiguous commits and imported history tests. Production nonce authority and actual AES-GCM whole-buffer execution remain out of scope.

## 6.9 Phase 11 — stable persisted schema and migration boundary

Metadata schema `LSMD` v2: ASCII magic `LSMD` (4 bytes), little-endian `UInt16` schema version = 2 and `UInt16` reserved flags = 0, then strict UTF-8 `UInt16`-length-prefixed text, `Byte`/`Int32` counts, little-endian `Int64` numbers, `Byte` retention hold. Order: ProviderId, KeyId, KeyName, key kind, algorithm, capability count and sorted capabilities, logical state, version high-water mark, version count, then per-version ordinal, state, hold and UTC ticks (0 means no deadline). CLR enums are encoded using **fixed ASCII names** (`symmetric`, `asymmetric-private`, `asymmetric-public`; `active`, `retired`, `deleted`; `pending`, `active`, `retired`, `deleted`), never runtime numeric values. Limits: 2048 versions, 64 capabilities, 1 MiB plaintext metadata and 256 bytes per text token. Duplicates, noncanonical ordering, appended bytes, unknown flags/versions, mismatched authenticated identity and invalid lifecycle state are rejected.

Legacy `LSM1` uses bytes `31 4D 53 4C` from its original little-endian `Int32` magic. Read it only **after successful IKeyStoreProtector authentication** and strict domain validation; never write v1 in new operations. `SoftwareKeyMetadataCodec.MigrateToCurrent` implements the current v1→v2 migration (idempotent v2→v2) **without storing anything**. A migration commit must re-protect the new plaintext under the **next** revision's associated metadata context, then CAS-replace the aggregate; on a stale revision, refresh trusted state, and on uncertain commit reconcile before further mutations. Independent monotonic authority is necessary to detect rollback between individually valid authenticated snapshots.

`LSPB` v1: `LSPB` marker, version and zero flags, canonical store-instance UUID and `ProtectorReference` as two length-prefixed tokens. This untrusted bootstrap contains no root secret; validate instance identity against trusted configuration and independently authenticate envelopes with their AAD. `LSNC` v1: `LSNC` marker, version and zero flags, exact `KeyReference` token, `UInt32` prefix, `UInt64` next counter, `UInt64` authority epoch. `ValidateSuccessor` detects local regression only when comparing trusted authority checkpoints and does **not** establish rollback protection. Concrete FileSystem crash recovery/atomic updates belong to Phase 12. Independent golden fixtures are included under `tests/Laveyana.Security.Tests/Fixtures`.

**Gate:** .NET 10 compilation and running NUnit golden, migration, corruption, future-version and mapping tests are required to close Phase 11.

## Phase 12 — FileSystem prototype and security gate

The experimental `FileSystemKeyStore` implements `IKeyStore` with an `LSFS` v1 snapshot containing an `LSFB` v1 body (names, revisions, protected envelopes, historical KeyId reservations). A SHA-256 digest of the body is authenticated by a mandatory external `IKeyStoreProtector`, with domain-separated AAD `Laveyana.Security/fs/v1/snapshot/{storeInstanceId}`. `LSPB` carries non-secret bootstrap identity and protector reference, with an optional trusted expected store UUID. The versioned formats are bounded and reject malformed, duplicate and trailing data. Routing names/identifiers are not encrypted, but all key material is already encrypted in protected envelopes.

All cooperating instances acquire a common exclusive lock file before reading state. A transaction writes and flushes a full temporary snapshot and replaces the committed file in one operation. Temporary files are removed only after the committed snapshot authenticates. Missing or corrupted snapshots must fail closed, not reset. File-system rename and flush guarantees depend on the host; directory fsync and adversarial path replacement are outside Phase 12.

**Release gate:** writes are off by default, with explicit `EnableExperimentalWrites` for tests only; no production secrets until Phase 13 validates ACL/owner/mode, inheritance, symlink/reparse, each path component, and TOCTOU. Authenticated snapshot integrity does not prevent valid historical snapshot replay. `ProvidesRollbackProtection=false`, no deterministic nonce allocator. Real cross-process failure/crash and platform validation remain release requirements.

## Phase 13 — platform-hardening implementation checkpoint

The storage adapter now checks every Linux root ancestor via `statx(AT_SYMLINK_NOFOLLOW)` and validates owner and write permissions. The private root requires owner `0700`; store files require owner-only permissions and regular-file type. The pinned directory descriptor and `openat(O_NOFOLLOW)` prevent final-component symlink following; locks use Linux advisory `flock`, and snapshot replacement uses directory-relative `renameat`/`renameat2(RENAME_NOREPLACE)` followed by directory `fsync`. Path-based enumeration of orphaned temporary names is never used to open/delete outside the pinned directory. Files with unexpected ownership, permissions or type fail closed; permissions are not repaired silently.

Windows creates an isolated DACL (owner, SYSTEM, Administrators), verifies existing file/root ACLs and checks ancestor permissions/reparse points. **Windows still uses pathname-based file access and rename; fully handle-relative/identity-pinned I/O and adversarial race testing are outstanding.** Unsupported OSes fail closed. Existing root-protector contract and `ProvidesRollbackProtection=false` are unchanged. The experimental write gate remains mandatory; no production readiness is claimed until .NET 10 builds, platform tests, ownership/ACL and race stress, and filesystem durability checks pass.


### Phase 14 implementation — Windows DPAPI CurrentUser (interim)

`Laveyana.Security.Windows` implements `IKeyStoreProtector` with Win32 `CryptProtectData`/`CryptUnprotectData` in CurrentUser scope with UI forbidden and without `CRYPTPROTECT_LOCAL_MACHINE`. No application-owned root secret is created. `LSWP` v1 encodes magic/version/length and opaque DPAPI ciphertext. Optional entropy is SHA-256 over domain tag, exact `ProtectorReference`, purpose and length-prefixed AAD. Internal plaintext includes magic/length, SHA-256 record checksum and payload; this is not an independent keyed MAC, since DPAPI remains the trust boundary. Unknown versions and wrong identity/purpose/context fail closed. Native plaintext is cleared before `LocalFree`, managed plaintext is returned only as an owned `SensitiveMaterialLease`. AAD is limited to 64 KiB. Construction fails outside Windows.

Tests cover fresh instances, wrong purpose/context, ciphertext tampering, generation changes, cancellation and unsupported OS. Legacy generations, re-protection and rollback resistance are not implemented. Windows .NET execution is mandatory for acceptance; FileSystem writes remain experimental.


## Phase 14A — explicit protector migration and re-protection

`Laveyana.Security.Protection.ProtectorGenerationRouter` wraps one **current-write**
`IKeyStoreProtector` plus explicitly registered historical **read-only** generations.
Envelopes are routed by their full persisted `ProtectorReference`, with no guessing,
trial decryption, plaintext fallback or opportunistic rewriting during ordinary reads.
Unregistered generations fail closed. Registrations marked `Compromised` are rejected:
re-wrapping a potentially exposed key is **not** a substitute for key rotation or an
incident-response assessment. Status is an explicit application configuration, not an
independent persisted compromise registry.

`Laveyana.Security.Software.SoftwareKeyReprotectionService.ReprotectAsync(LogicalKeyHandle)`
handles **one named logical generation by exact ProviderId/KeyId**. It authenticates
its metadata and every non-deleted material version at a consistent expected revision;
then protects historical material under the current generation, re-encodes metadata
as `LSMD v2`, binds metadata to `revision + 1` and CAS-replaces the entire aggregate
in **one** store transaction. Existing current-generation material remains unchanged.
`KeyReference`, raw cryptographic material, version history, active version, algorithm,
capabilities and retention are preserved. CAS conflicts fail without retries; write
exceptions have **unknown commit status** and must be reconciled against the store.
On a confirmed successful CAS, no live material envelope from a legacy generation
remains. A confirmed `AlreadyCurrent` result does not claim a globally atomic read.

The transaction supports at most **128 non-deleted material versions**; larger aggregates
fail closed rather than partially migrate. No store enumeration or global/batch
migration is provided. A store must actually implement durable, atomic `TryReplaceAsync`.
Snapshot rollback remains undetectable without independent monotonic authority;
re-protection cannot cure already exposed cryptographic keys. Windows DPAPI generation
changes do not necessarily change the underlying DPAPI user root key. Keep historical
readers until all required aggregates are migrated, verified and covered by recovery
planning. Disabling a legacy reader before this may make backups unreadable. This
stage and FileSystem remain **non-production** until the .NET 10 test/build and
cross-platform filesystem security gates pass.

```csharp
using Laveyana.Security.Abstractions.Handles;
using Laveyana.Security.Abstractions.Protection;
using Laveyana.Security.Protection;
using Laveyana.Security.Software;

// existingStore, providerId, keyId and historic/current protectors are supplied by the host.
ProtectorGenerationRouter router = new(currentProtector,
    [new HistoricalProtectorRegistration(oldProtector, HistoricalProtectorStatus.LegacyReadOnly)]);
SoftwareKeyReprotectionService migration = new(providerId, existingStore, router);
KeyReprotectionResult result = await migration.ReprotectAsync(new LogicalKeyHandle(providerId, keyId));
// Reconcile authoritative storage after any SoftwareKeyCommitUncertainException.
```


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

**Additional Phase 14A defense:** newly protected envelopes and the outer snapshot are decrypted and compared against their input **before** any commit attempt. This does not replace independent protector validation, review and real .NET/Windows/Linux testing.


### Phase 16 managed AES-GCM executable contract (provisional)

`IAuthenticatedEncryptionBackend` exposes whole-buffer and detached Encrypt/Decrypt/TryDecrypt APIs using authenticated `EncryptedPayload` result models. The software implementation supports AES-256-GCM only. Encryption validates the logical handle, fetches and authenticates metadata, selects exact Active material, and uses an IKeyStore revision-consistent material read to establish the operation's snapshot before nonce issuance. Ciphertext is committed to an exact historical KeyReference plus the Phase 15 canonical application AAD. Decryption enforces the recorded AES algorithm and exact Active/Retired version with `Decrypt` capability, never uses a newly rotated version implicitly. `TryDecrypt` returns null for `AuthenticationTagMismatchException` only and wipes partially written plaintext. Message sizes are limited to 16 MiB and application AAD to 64 KiB. Default randomized nonce budgets are process-scoped, NOT cross-process, restart or rollback assurances. Deterministic allocation requires an explicitly supplied independent rollback-safe authority and a trusted store capability; failed allocation cannot downgrade to randomized. Input plaintext is copied and wiped. Source/test acceptance is provisional until .NET 10 execution and platform hardening.

### Phase 17 managed HMAC and digital signature execution contract (provisional)

`IManagedMacBackend.ComputeMacAsync` accepts an exact logical handle and bounded message (<=16 MiB), reads authenticated software metadata, validates Active key + `Mac` permission, reads material with the same optimistic revision and calculates a full HMAC-SHA-256/384/512. The immutable `MacResult` records the exact provider/key/version and algorithm. `VerifyMacAsync` does the same for exact Active or Retired material with the independent `VerifyMac` permission, uses `CryptographicOperations.FixedTimeEquals` for equal-length full tags and returns `false` **only** on mismatch. Deleted/Pending material, profile/capability mismatch, store conflict, protector failure and cancellation are exceptions. Historical verification must not switch automatically to the newest key.

`IManagedSignatureBackend.SignAsync` and `.VerifySignatureAsync` work with exact versioned `SignaturePayload`. `ManagedSignatureBackend` validates fresh provider declarations, logical and exact version metadata and signature algorithm policy. The backing `IVersionedSignatureKeyOperations` MUST enforce actual key-version access at the operation boundary; this interface never exports private material. Implementations must preserve the failure distinction: false only when a cryptographically checked signature is invalid, never on authorization or material errors. New signatures: ECDSA-P256-SHA256 using IEEE P1363 (64 bytes); RSA-PSS-SHA256 using new private keys at least 3072 bits, raw signature length consistent with modulus. No RSA PKCS#1 v1.5 signing, implicit SHA-1 downgrade or silent fallback. Verify may use Active/Retired public/private key versions; Sign requires Active private key.

`EphemeralSignatureKeyOperations` is an actual .NET signer/verifier for process-local ECDSA/RSA keys, with transferred object ownership and secure disposal, but **not** durable, multi-process or independently revocation-aware. The existing software lifecycle does not generate, persist or rotate asymmetric key pairs. Production signing requires an audited `IVersionedSignatureKeyOperations` backed by trusted durable storage, system KSP, HSM or remote service. All Phase 17 formats are provisional until .NET 10 compilation/interoperability and negative NUnit tests complete.

### Phase 18 — provisional agreement/derivation contracts

`DerivationContext` (1–64 lowercase ASCII purpose, 1–256 bytes application context, 16–64 derived bytes) uses versioned length-prefixed big-endian transcripts. ECDH uses a sorted pair of canonical P-256 SPKI values; symmetric HKDF binds exact `KeyReference`. Independent labels are `Laveyana.Security/ECDH-P256/HKDF-SHA256/v1` and `Laveyana.Security/Symmetric/HKDF-SHA256/v1`. Fixed HKDF-SHA-256 uses the raw ECDH shared secret or protected symmetric source as IKM and `salt=SHA256(info)`; changing purpose/context/participants/length changes output. These wire parameters are provisional until .NET interoperability tests and focused review.

Provider-owned metadata checks never authorize use alone; executor MUST revalidate exact Active status and revocation. `DerivedKeyLease` exposes a synchronous borrowed-only visitor and wipe-on-Dispose, not default raw export; opt-in `IDerivedMaterialExportPolicy` gates copies. Ephemeral ECDH is process-only, not authenticated peer exchange or durable key management. Callers must authenticate peer SPKI and protocol transcript to prevent active MITM.


### Phase 19 — gate-only HPKE analysis (not implemented)

The conditional RFC 9180 `Seal/Open` feature remains **unsupported**. Exact reference suite: Base / DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM as in Appendix A.3.1. Candidate future AES-256-GCM production suite needs its **own** official vectors and approved interoperability tests. The offline `tools/hpke_gate_verify.py` checks the public test vector and negative cases; it cannot validate a .NET HPKE implementation. Do not reuse the Phase 18 KDF transcript, announce HPKE capabilities, or expose a partial SealedPayload. Refer to `Laveyana.Security.HpkeGate.md` for mandatory wire-format, authenticated exact key identity, revocation, trust, replay and release criteria.

### Phase 20 — verified source-level streaming boundaries

SHA-256/384/512 streaming is local and independent of key stores. Full-length HMAC-SHA-256/384/512 streams route through optional `IStreamingMacBackend` in Abstractions and the software backend; historical verification requires the exact version and VerifyMac capability. Input is consumed to EOF with at most 64 KiB of rented buffer; default byte limit 1 TiB with optional exact trusted input length. Stream ownership stays with caller. Cancellation, I/O, size, length, capability and revision-change failures throw; only a mismatching authenticated tag yields false. No stream AEAD protocol or ciphertext encoding was introduced; the encrypted-streaming gate is documented in `Laveyana.Security.StreamingGate.md` and remains DEFERRED. .NET tests/build unconfirmed.


### Phase 21 — secrets provider contract and scoped material

External secret plugins depend only on Abstractions and implement the read-only `ISecretProvider`. `FindAsync` returns `SecretDescriptor?`, and `GetAsync` returns `SecretReadResult?` with an exact reference and an **owned** `SensitiveMaterialLease`. Null means absent, not unauthorized. `SecretHandle` and `SecretProviderRegistry` check the reference and provider identity after asynchronous reads and zeroize owned data even when the visitor, cancellation or validation fails. No raw byte/string getter, implicit conversion, JSON serialization or universal secret version is added. The scoped visitor is synchronous; it must not save the span or start asynchronous use of it.

A provider advertises `CanOpenMaterial` and `CanExportMaterial` independently, defaults deny both; metadata is never an access grant, and a callback cannot physically prevent a deliberate byte copy. Providers implement their own authorization and resource-level revocation. Optional `ISecretManagementProvider` provides `SetAsync` and `DeleteAsync` with provider-defined semantics, routed only by an explicit request. Registration rejects duplicate IDs/aliases or changed provider identity. No default backend or guaranteed long-term secret persistence is provided. Build and NUnit tests remain pending.



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

## Phase 25 — Observability implementation boundary

`SecurityObservability` optionally observes managed operations without receiving
sensitive inputs and without rewriting the operation result. Public event dimensions
are bounded enumerations, not key names or exception messages. Metrics:
`laveyana.security.operations` (counter), `laveyana.security.operation.duration`
(histogram, ms), and `laveyana.security.audit.delivery_failures` (identity-free counter).
The activity source is `Laveyana.Security`. Structured logging includes only
`Operation` and `Outcome`.

`ISecurityAuditSink` is neither a transactional audit-of-record nor a guarantee of
delivery. A trace ID may appear in a separate audit event but never as a metric
label. Applications manage listeners, ILogger providers, metric exporters, and audit
persistence. Unconfigured telemetry cannot affect library behavior.

