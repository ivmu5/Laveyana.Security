# Laveyana.Security — Phase 27 security review

**Date:** 2026-10-10  
**Baseline:** `Laveyana.Security_Phase26_2026-10-10.zip`  
**Status:** **PARTIAL / RELEASE BLOCKED**. This is a record of static review and source changes, **not** a completed security certification or Phase 27 acceptance.

Seven assemblies and their dependency boundaries were statically reviewed, together with managed AEAD/MAC/signature/agreement, the nonce engine, sensitive memory, persisted formats, FileSystem, Linux/Windows guards, DPAPI, error handling and observability. Repository and documentation checkers, including their self-tests, passed. **No .NET 10 SDK was available**; restore/build/NUnit, live codec fuzzing, platform-specific tests, cross-process adversarial tests, crash durability and independent security review **were not executed**.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| SA-01 | **BLOCKER** | Actual .NET build and test matrix unverified (`global.json`, CI workflow). | Open |
| SA-02 | **HIGH** | Windows FileSystem uses path-based opens and `File.Move` after pathname/ACL prechecks; concurrent path replacement remains possible (`FileSystemKeyStore`, `WindowsStorePathGuard`). | Open; experimental writes only |
| SA-03 | **HIGH** | An authenticated old snapshot can be replayed: local manifest hashing is not independent rollback protection (`FileSystemKeyStore.Capabilities`, `LoadAsync`). | Open |
| SA-04 | **HIGH / GATE** | Randomized AES-GCM nonce invocation budget is per-process, not durable across restarts/restores or independent hosts (`AeadNoncePolicyEngine`). | Open infrastructure invariant |
| SA-05 | **MEDIUM** | Awaiting an optional audit sink with `CancellationToken.None` can indefinitely delay an otherwise completed operation (`SecurityObservability`). | Open |
| SA-06 | **MEDIUM** | Caller-mutated AEAD AAD after async suspension could change the operation input. | Source fixed; new NUnit tests unrun |
| SA-07 | **MEDIUM** | Caller-mutated signature message after metadata await could change the signed or verified input. | Source fixed; new NUnit test unrun |
| SA-08 | **RELEASE GATE** | Linux/Windows ownership, ACL, file-descriptor and DPAPI behavior needs live adversarial, cross-process testing. | Open |
| SA-09 | **LIMITATION** | Asymmetric executors are ephemeral, with no durable private-key store/revocation. | Documented, not production |

No confirmed exploited CRITICAL issue was established by this **limited** review; this does not imply that none exists. HPKE and streaming AEAD remain unsupported, and secret-provider authorization remains provider-specific.

## Source changes

- Snapshot and clear AAD at AEAD call entry (with bounded allocation).
- Snapshot and clear signature message at signing/verification call entry.
- Add two AEAD delayed-I/O mutation tests, one signature delayed-I/O test and a deterministic mutation corpus for all four managed result wire formats.
- Public API contracts and wire schemas are unchanged; the new tests have **not** been executed.

## Release-gate matrix

**Required before GO:** .NET SDK 10 restore and warnings-as-errors Release build; full NUnit on Windows and Linux; live fuzz and golden-vector checks; Windows reparse/ACL race tests; Linux descriptor/locking/crash tests; DPAPI wrong-user and unavailable-profile tests; independent rollback-resistant authority with multi-process nonce assurance; lifecycle/CAS/fault injection including uncertain commits; dependency/API compatibility review; and independent security sign-off.

**Decision: NO-GO.** Phase 27 remains open. Prioritize a real .NET 10 build/test baseline, then resolve SA-02/03/04 and re-run adversarial platform tests and security review.
