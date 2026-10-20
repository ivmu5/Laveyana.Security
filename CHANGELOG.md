# Changelog

**English** | [Русский](CHANGELOG.ru.md)

This changelog records **unreleased development checkpoints**, not production releases or successful security acceptance. Version configured in `Directory.Build.props`: `1.2610.0-alpha.1`. No public package, compatibility promise or release tag is asserted by this document.


## Unreleased — SA-03 Stage 2B2: authenticated candidate staging (2026-10-20)

- Add an internal handle-relative two-file journal for the exact next snapshot and root-protector-authenticated request intent; checkpoint, pinned store UUID and distinct prepare/finalize IDs are bound and checked.
- The journal is never silently overwritten or discarded. Add six Windows/Linux integration scenarios for exact byte recovery, duplicate attempts, tampering, partial generations and identity/digest binding.
- **Not a writable protected profile:** no authority RPC, no recovery or downgrade pin, and Windows directory power-loss durability is unproven. `ProvidesRollbackProtection=false`; SA-03/SA-04/SA-08 OPEN, Phase 27 NO-GO.

## Unreleased — SA-03 Stage 2B1: read-only rollback inspection (2026-10-20)

- Add optional `FileSystemKeyStoreOptions.RollbackAuthority` **for experimental read-only inspection only**. Every load authenticates the exact file bytes, reads an external checkpoint and requires a committed match with no pending transition. Missing/foreign/outdated/pending authority state fails closed; network exceptions propagate.
- Reject experimental writes, migration opens and unpinned store UUID when this option is used; no cleanup or fallback. Add seven cross-platform integration tests using a volatile authority test double.
- **Not protected mode / not production safety**: ordinary `OpenAsync` without the option can still bypass the check; downgrade prevention, safe durable staging, commit/recovery, server authority, SA-04 and SA-08 remain OPEN. `ProvidesRollbackProtection=false`, Phase 27 NO-GO.

## Unreleased — SA-03 Stage 2A: request resolution contracts (2026-10-20)

- Add an optional, source-compatible request-aware rollback authority contract with durable per-request decisions and mandatory fencing of late RPCs before declaring `NotApplied`.
- Add immutable `RollbackRequestId` and three-way `RollbackRequestResolution` outcomes. Existing Stage 1 contracts remain unchanged.
- Add eleven NUnit contract tests with a deliberately volatile fake for delayed prepare/enroll, lost replies, idempotency, tuple/UUID binding and prevention of untracked mutation bypass.
- Extend the required CI TRX test list for key request-fencing regressions; update the rollback authority design notes (EN/RU), including durable candidate/intent staging BEFORE any request is sent. **No remote provider, FileSystem integration or production guarantee. SA-03/SA-04 OPEN; Phase 27 NO-GO.**

## Unreleased — Phase 27: F-02 / SA-05 non-blocking optional audit (2026-10-20)

- Dispatch `ISecurityAuditSink` callbacks off the cryptographic operation path. Blocking synchronous or never-completing asynchronous sinks cannot delay operation completion or change its success/exception.
- Introduce a fixed process-wide in-flight budget of eight audit callbacks, with no pending queue or retry. Overflow events are dropped and counted by the existing `laveyana.security.audit.delivery_failures` metric. Late callback exceptions are swallowed and counted.
- Prevent propagation of the caller's `ExecutionContext` to audit callbacks. Deliveries may overlap, arrive out of order, or be lost on process shutdown; they are **not** a compliance-grade, durable audit-of-record.
- Update observability tests for asynchronous arrival; add regressions for async hangs, synchronous blocking, bounded overload and ambient context isolation. No new public types or dependencies. SA-03/SA-04/SA-08 remain open; **Phase 27 production NO-GO**. NUnit validation is required.

## Unreleased — Phase 27: F-05 FileSystem lock timeout validation (2026-10-20)

- Use one internal `LockTimeout` range check for both regular and migration store opens: positive values up to five minutes, inclusive.
- Add Windows/Linux integration regressions for invalid and boundary timeout values, checking that invalid opens do not mutate store files.
- No public API, snapshot format, or locking behavior changes. SA-03/SA-04/SA-05 remain open; **Phase 27 production NO-GO**.

## Unreleased — Phase 27: F-01 tracing isolation (2026-10-20)

- Isolated `Activity` creation, callbacks and disposal from managed operation outcomes; best-effort cleanup restores the previous ambient tracing context after listener failures.
- Added NUnit regressions for throwing tracing sampling/start/stop callbacks, original exception identity, single execution and an actual committed key creation.
- No public API changes; SA-05 audit-sink liveness and SA-03/SA-04 remain open. **Phase 27 production NO-GO.** The new tests require .NET execution.

## Unreleased — SA-03 contract stage 1 (2026-10-20)

- Added an optional independently trusted rollback authority contract, whole-snapshot checkpoints, and fail-closed comparison gate in Abstractions. Added NUnit contract tests and bilingual design/security notes.
- No FileSystemKeyStore integration, trusted authority provider or nonce changes; **SA-03/SA-04 OPEN, Phase 27 NO-GO**. Build/tests require verification on .NET SDK 10.

## Unreleased — H01 infrastructure closeout (2026-10-16)

- **H01 closed (build, CI and repository hardening only):** successful required checks, protected `master`, three merged Pull Requests and a passing manual extended regression on Windows/Ubuntu. See the [H01 closure record](docs/hardening/H01-Setup.md).
- **Phase 27 remains open / production NO-GO:** SA-02, SA-03, SA-04, SA-05 and SA-08 require targeted mitigation, tests and security review. This documentation-only closeout does not alter cryptographic behavior.

## Unreleased — H01: extended regression workflow (2026-10-16)

- Removed duplicate `Verify` runs on open Pull Request branches: Pull Requests are checked once, and pushes to `master` are verified after merge. All three required check names remain unchanged.
- Added a separately scheduled/manually triggered extended regression workflow with five sequential full NUnit runs per OS, per-attempt platform-aware TRX verification, locked restore, Release build, 14-day report artifacts and a per-runner timeout. The normal required `Verify` checks remain unchanged.
- Updated the extended regression schedule from daily to the **first day of each month at 02:17 UTC**, while retaining manual dispatch; the GitHub workflow is displayed as `Extended Regression` (the existing `nightly.yml` filename is retained).
- The [first manual run](https://github.com/ivmu5/Laveyana.Security/actions/runs/38908695165) on `master` passed on Windows and Ubuntu on 16 October 2026. This is additional regression coverage, **not** security acceptance or closure of Phase 27 findings.

## Unreleased — H01: compiler diagnostic fixes (2026-10-16)

**H01 verification update (16 October 2026):** Both hosted runners now pass `Verify`: `Source & docs`, `Build & NUnit (ubuntu-latest)`, and `Build & NUnit (windows-latest)`. Added dependency lock files; resolved CI-only Windows ACL token-owner behavior, Linux secure-descriptor stream initialization, and Linux test `umask` assumptions. Installed the active `Protect master` ruleset requiring PRs and the three checks. These milestones close the initial build/CI setup, **not** Phase 27 security acceptance.

The historical entries below describe the evidence available when each change was made; earlier “unverified” statements are superseded by the above CI run, not by a production-security sign-off.

- Fixed `CS0618` (NUnit), `CS9174` (`ReadOnlyMemory<byte>`) and Windows-only platform analyzer `CA1416` warnings.
- Eliminated test-assembly `CS1591` by disabling XML documentation output **only** for test projects; shipping library API documentation remains mandatory.
- Retained NuGet lock files and excluded `.vs`, `bin`, `obj` from the archive. At this checkpoint, compilation and NUnit were not yet verified (subsequently verified by H01 CI).

## Unreleased — H01 build corrections (2026-10-12)

- Fixed 52 missing-braces constructs and documented 46 public enum values with XML comments.
- Separated top-level types into independent files without changing public API signatures; original IDE0011/CS1591 causes have been addressed, while cascading CS0006 errors require a fresh compilation.
- Added `tools/verify_api_layout.py` to CI and the [correction report](docs/hardening/H01-CompilationRepair.md).
- **.NET compilation and NUnit remain unverified; Phase 27 production NO-GO remains in effect.**

## Unreleased — Phase 27 (partial review, 2026-10-10)

- Static security review of seven projects and a [prioritized findings report](docs/audit/Laveyana.Security.Phase27.SecurityAudit.md).
- Snapshot mutable AEAD AAD and signing input before asynchronous metadata I/O; wipe private snapshots on completion.
- Added delayed-I/O input mutation regressions and deterministic wire-format mutation tests.
- **Phase 27 and the production release gate remain open:** .NET build/NUnit/platform tests are unrun; Windows TOCTOU, rollback and nonce lifetime invariants remain unverified.

## Unreleased — Phase 26 (2026-10-10)

- Reconciled README, specification, architecture and roadmap against the Phase 25 repository baseline.
- Added a bilingual source-capability/status matrix and explicit **not verified** build/test/security gates.
- Marked HPKE and streaming AEAD deferred, FileSystem experimental and persistent asymmetric/secret backends incomplete.
- Clarified the Decision Log's intentional numbering gaps; no historical decisions were recreated or silently renumbered.
- Added automated documentation verification and CI integration. No cryptographic runtime behavior is changed in Phase 26.

## Unreleased — implementation checkpoints

| Phase | Scope introduced | Acceptance state |
| --- | --- | --- |
| 1–4 | Repository, identities, safe local primitives and sensitive material | Source prepared; .NET/NUnit unverified |
| 5–8 | Typed handles, lifecycle planner, provider and store contracts | Source prepared; .NET/NUnit unverified |
| 9–11 | Software lifecycle, nonce policy, versioned persisted schemas | Source prepared; .NET/NUnit unverified |
| 12–13 | FileSystem store and platform confinement | **Experimental; security gate open** |
| 14–14A | Windows DPAPI and explicit protector re-protection | Source prepared; platform tests unverified |
| 15–18 | Payloads, AES-GCM, HMAC/signatures, agreement and derivation | Source prepared; .NET/NUnit unverified |
| 19 | RFC 9180 reference verification and HPKE gate analysis | **HPKE API deferred / unsupported** |
| 20 | Streaming SHA/HMAC and separate streaming gate | SHA/HMAC source prepared; **AEAD unsupported** |
| 21–22 | Secrets management contracts and DI composition | Source prepared; .NET/NUnit unverified |
| 23–24 | Optional conditional rotation and provider migration primitives | Source prepared; durable coordination is external |
| 25 | Opt-in logging, metrics, tracing, best-effort audit | Source prepared; .NET/NUnit unverified |

See [Roadmap](docs/design/Laveyana.Security.Roadmap.md), [Decision Log](docs/design/Laveyana.Security.DecisionLog.md) and [README](README.md) for detailed capabilities and blockers. Phase 27 has a partial static review, but the **full security acceptance remains open**.
