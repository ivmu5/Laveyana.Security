# Laveyana.Security — Phase 27 security review

**English** | [Русский](Laveyana.Security.Phase27.SecurityAudit.ru.md)

**Review date:** 10 October 2026  
**Reviewed baseline:** `Laveyana.Security_Phase26_2026-10-10.zip`  
**Result:** **PARTIAL / RELEASE BLOCKED.** The original scope was static review and initial source corrections; it was not a final security acceptance.

## Scope and method

Reviewed the boundaries of seven projects, AES-GCM/HMAC/ECDH/signature provider code, the nonce engine, protected persistence, Linux and Windows path guards, Windows DPAPI, sensitive memory, audit/telemetry, input/output contracts, existing tests and CI configuration. The reviewers followed execution/exception paths, historical key versions, input bounds, defensive copies and secret-buffer clearing. `tools/verify_repository.py` and `tools/verify_documentation.py` and their self-tests completed. Mutation tests for four serialized formats and suspended-I/O input mutation regressions were added.

**Not performed during the 10 October static review:** `dotnet restore`, `dotnet build`, NUnit, live Windows DPAPI tests, cross-process races, reparse-point substitution, power-loss simulation and executable decoder fuzzing. The later H01 update below records the build/test evidence that became available on 16 October; it must not be retroactively ascribed to this original review.

## Findings by severity

| ID | Priority | Evidence location | Observation and consequence | Original review status |
| --- | --- | --- | --- | --- |
| SA-01 | **BLOCKER** | `global.json`, CI workflow | No executed .NET 10 Release build or unit/integration NUnit evidence was available at the review checkpoint. | Open at review; updated by H01 |
| SA-02 | **HIGH** | `FileSystemKeyStore.cs` `AtomicWriteAsync`, `ReadBoundedAsync`; `WindowsStorePathGuard.cs` | Windows pre/post-checks paths but uses names for open/move; replacing a pathname between check and I/O can cause TOCTOU. | Open; experimental writes only |
| SA-03 | **HIGH** | `FileSystemKeyStore.cs` capabilities and `LoadAsync` | Authentication cannot detect replay of a previously valid snapshot. Key states, revisions and tombstones may revert without independent monotonic authority. | Open |
| SA-04 | **HIGH / GATE** | `AeadNoncePolicyEngine.cs`, `RandomBudgets` | A process-local randomized nonce budget cannot guarantee key-wide uniqueness across restarts, restores or independent processes; a deterministic allocator depends on external trusted state. | Open infrastructure requirement |
| SA-05 | **MEDIUM** | `SecurityObservability.cs`, best-effort sink | Awaiting an optional sink with `CancellationToken.None` may indefinitely delay the return from an operation whose core work already finished. Sink exceptions are suppressed, but an infinite wait is not. | Open |
| SA-06 | **MEDIUM** | `SoftwareKeyProviderBackend.Aead.cs` | Mutable AAD could change during suspended metadata lookup and alter the operation's authenticated context. | Source fixed at review; tests added |
| SA-07 | **MEDIUM** | `ManagedSignatureBackend.cs` | A mutable message was copied after async metadata lookup, making signed content differ from call-time input. | Source fixed at review; test added |
| SA-08 | **RELEASE GATE** | `FileSystemKeyStore.cs`, `LinuxSecureDirectory.cs`, `WindowsDpapiUserProtector.cs` | Ownership/ACL, descriptor-relative I/O, recovery, durability and P/Invoke require live adversarial tests on both OSes. | Open |
| SA-09 | **LIMITATION** | `EphemeralSignatureKeyOperations.cs`, `EphemeralEcdhKeyOperations.cs` | Asymmetric executors are temporary/in-process; persistent protected asymmetric keystore and durable revocation are unavailable. | Documented limitation |

### Applicability notes

- HPKE `Seal/Open` and encrypted AEAD streaming are **unsupported** pending their independent security gates.
- The concrete secret provider must enforce its own authorization; no universal application access policy is implied.
- `SensitiveMaterialLease` clears only the material it owns, not OS/runtime copies, callback copies or deleted disk blocks.
- Multi-process rollback protection and nonce uniqueness cannot be established by a local static check alone.
- No demonstrably exploited **CRITICAL** issue was confirmed by this incomplete review; this does not establish that none exists.

## Changes made in the original review

1. `SoftwareKeyProviderBackend.Aead.cs`: snapshot AAD before the first async suspension, check bounds before copying, clear the snapshot on every exit.
2. `ManagedSignatureBackend.cs`: snapshot the input message before lookup, clear the copy on failure and cancellation.
3. `SoftwareAeadEncryptionTests.cs`: two mutation tests for AAD while metadata lookup is suspended.
4. `ManagedMacSignatureTests.cs`: a signing/verification message-mutation test with paused metadata lookup.
5. `SecurityCodecMutationTests.cs`: deterministic byte mutations and invalid-input corpus for `LEP1`, `LDP1`, `LSP1`, `LMR1`; successfully parsing a format is not proof of authenticity.

Public API shapes and serialized wire formats were intentionally unchanged. Tests in this list were not executed during the original static-review checkpoint; subsequent H01 CI covered the repository NUnit suites.

## Mandatory release-gate matrix

| Gate | Required environment | Acceptance condition |
| --- | --- | --- |
| Restore / Release build / warnings as errors | Windows + Linux; pinned .NET SDK | Clean pass (H01 CI baseline obtained) |
| Full unit + integration NUnit | Windows + Linux | Tests pass; skipped tests must be justified by feature/platform gates (H01 CI baseline obtained) |
| Codec fuzz + versioned golden files | Executable .NET on both OSes | Bounded parsers, deterministic round trips, unknown-version rejection |
| Windows ACL, symlinks/junctions/reparse races | Windows, multiple processes, adversarial changes | Unable to redirect read/write outside the pinned trusted directory |
| Linux `openat`/`statx`/`flock`/`rename`/`fsync` | Linux, multiple processes and controlled crash | No race, ACL bypass or inconsistent transactions |
| Rollback restore and nonce lifetime | Actual selected store + allocator, multiple processes | No nonce reuse for one key version; fail closed on rollback |
| DPAPI CurrentUser / wrong user / unavailable profile | Windows | Fail closed, no plaintext fallback |
| Lifecycle, CAS, uncertain commit, rotation, migration | Fault injection and concurrent hosts | No version ID reuse or automatic retries after uncertain commit |
| Public API / nullable / vulnerability and dependency review | CI and manual review | No unreviewed breaking changes or known risky dependencies |
| Independent security review | Independent specialist | Documented disposition of residual risks |

## Release decision

**NO-GO** for production and real secrets. Phase 27 is **not accepted**. After obtaining build/NUnit evidence, the remaining priorities are SA-02/03/04, platform adversarial tests and a repeat full security review. A successful static or automated test suite does not replace those gates.

## H01 verification addendum — 16 October 2026

This section updates the *evidence*, not the original Phase 27 static-review scope or its architectural decisions.

- SA-01: a verified build/NUnit baseline **now exists**. GitHub Actions `Verify` passed source/docs, Release builds and NUnit on both Windows and Ubuntu.
- Subsequent CI fixes addressed Windows ACL current-user vs token-owner behavior, Linux native-descriptor stream construction, and `umask`-dependent test setup of a group-writable ancestor. They do not by themselves close all filesystem security risks.
- The active `Protect master` ruleset requires PRs and all three checks. This is development-process hardening, not a security certification.
- SA-02 (Windows TOCTOU), SA-03 (rollback), SA-04 (durable nonce constraints), SA-05 (best-effort audit latency), SA-08 (adversarial platform coverage), and other release criteria remain **open**. Green CI cannot establish absence of untested vulnerabilities.

**Release decision remains NO-GO.** Reproducible verification commands are in [H01](../hardening/H01-Setup.md).
