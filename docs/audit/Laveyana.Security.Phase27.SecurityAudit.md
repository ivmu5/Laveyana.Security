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

## SA-02 — Windows TOCTOU remediation candidate (16 October 2026)

**Before:** Windows read, stage, rename, lock, and temporary-file cleanup relied on pathname-based operations. ACL/reparse checks occurred separately; swapping a pathname between validation and I/O could redirect an operation.

**Change:** `WindowsSecureDirectory` holds a root directory handle; child files are opened relative to it with no-follow checks. ACL and ownership checks operate on the opened handles. Staged-file replacement and deletion use handles; pending-file enumeration is bound to the same directory handle. `FileSystemKeyStore` routes Windows I/O through this internal backend; Linux behavior, `IKeyStore`, and serialized formats remain unchanged. Windows integration tests cover symbolic-link rejection and use of a pinned root after pathname rename.

**Status: EXPERIMENTAL / TEST ONLY; SA-02 OPEN.** The initial candidate had not been tested on Windows when written; later build/test results and the native rename correction are recorded below. Adversarial testing is still outstanding. It does not promise isolation against processes under the same identity, rollback protection or crash durability. `EnableExperimentalWrites` remains mandatory; Phase 27 remains **NO-GO** for production secrets.

## SA-02 Windows first integration run and native rename correction — 16 October 2026

The initial experimental Windows implementation compiled in Release on .NET 10, but the first Windows integration run reported **71 total: 35 passed, 22 failed, 14 not executed (platform skips)**. All 22 failures traced to `WindowsSecureDirectory.Move`: `SetFileInformationByHandle(FileRenameInfo)` rejected a relative destination with a non-null directory handle (`ERROR_INVALID_PARAMETER`, Win32 error 87). These were cascading initialization failures, not 22 independent security findings.

**Correction candidate:** staged-file rename now calls `NtSetInformationFile(FileRenameInformation = 10)` with the verified source handle and the already-pinned destination directory handle. It retains atomic collision behavior via `ReplaceIfExists` and does **not** fall back to pathname-based `File.Move` or an absolute-name Win32 rename. The new native return status is translated to a Windows error on failure. All other project APIs and serialized formats remain unchanged.

**Verification status:** correction prepared but **not yet re-run on Windows**. SA-02 remains **OPEN / EXPERIMENTAL / TEST ONLY**, and Phase 27 remains **NO-GO**. Repeat Windows integration tests and follow with adversarial race / ACL / junction, crash-recovery and Linux regressions before any production claim.

## SA-02 Windows second integration run — 16 October 2026

With the native handle-relative rename fix applied, the Windows Release (.NET 10) integration run reported **71 total: 54 passed, 3 failed, 14 not executed**. The previous common `ERROR_INVALID_PARAMETER` (87) rename failure was not observed.

All three remaining failures occurred **in the test setup** while attempting `File.CreateSymbolicLink` or `Directory.CreateSymbolicLink`, before the storage guard was exercised. Windows rejected symbolic-link creation with a missing privilege (Win32 `ERROR_PRIVILEGE_NOT_HELD`, 1314). The current test only recognized `UnauthorizedAccessException` but .NET returned `IOException`. The three test cases are `WindowsSnapshotSymlinkIsRejectedWhenSupported`, `WindowsExistingLockSymlinkIsRejectedWhenSupported`, and `WindowsRootDirectorySymlinkIsRejectedWhenSupported`.

**Test-harness correction:** ignore those tests *only* when symlink creation throws `IOException` with HRESULT `0x80070522` (`HRESULT_FROM_WIN32(1314)`), preserving failures for unrelated I/O exceptions. An `Ignored` result is **not a security pass**. Enable Windows Developer Mode or run in an environment granted symbolic-link creation privileges, then rerun all three to obtain actual security evidence.

**Status: SA-02 remains OPEN / EXPERIMENTAL / TEST ONLY; Phase 27 remains NO-GO.** Windows symbolic-link checks are unverified in this environment. Further adversarial race, ACL, junction and crash tests are required, as is Linux regression testing.

## SA-02 — third Windows run: lock-file rejection error handling (16 October 2026)

The Windows export (.NET SDK 10.0.402) reported **367 tests: 352 passed, 1 failed, 14 expected platform skips**. All three Windows symlink tests now executed. `WindowsSnapshotSymlinkIsRejectedWhenSupported` and `WindowsRootDirectorySymlinkIsRejectedWhenSupported` passed; `WindowsExistingLockSymlinkIsRejectedWhenSupported` exposed an error-handling defect.

**Root cause:** `WindowsSecureDirectory.OpenChild` correctly rejected the `.store.lock` symbolic link with an `IOException` ("unsafe reparse point or type"). However, the Windows branch of `FileSystemKeyStore.AcquireLockAsync` caught **all** `IOException`s, retried until `LockTimeout` (15 s in the recorded run), then hid the security rejection behind a `TimeoutException`. The unsafe link was not followed, but the failure was misleadingly reported as lock contention and delayed execution.

**Correction candidate:** only verified native lock contention (`ERROR_SHARING_VIOLATION`, 32; `ERROR_LOCK_VIOLATION`, 33) can enter the Windows retry/timeout path. The code inspects `IOException.HResult` or an inner `Win32Exception.NativeErrorCode`. All other I/O errors (including unsafe reparse points) immediately propagate with their original type and stack. Linux lock behavior, genuine-contention timeout policy, public APIs and persisted formats are unchanged. The existing `.store.lock` integration test is a regression check that failed before this change and should pass afterwards.

**Status: candidate prepared, Windows build and tests have not yet been rerun. SA-02 OPEN / EXPERIMENTAL / TEST ONLY; Phase 27 NO-GO.** Adversarial file/directory swapping races, junction/reparse, ACL tests and Linux regressions remain necessary.

## SA-02 — fourth Windows run and adversarial test candidate (2026-10-16)

A Windows export (.NET 10.0.402 / Release) after the `AcquireLockAsync` fix reported **367 tests: 353 passed, 0 failed, 14 expected platform skips**. All three Windows symlink tests actually executed and passed. These TRX results are functional evidence, not proof that all TOCTOU attacks are excluded.

**Next test candidate (not yet executed):** two new `Adversarial` tests exercise concurrent writes after an opened store directory is renamed and its old pathname is replaced, and concurrent replacement of the snapshot name with a symlink to an external sentinel during reads. Safe I/O rejection is accepted; unauthenticated data is not. The tests touch disposable test directories only. Public APIs and production store code remain unchanged.

**SA-02 remains OPEN / EXPERIMENTAL / TEST ONLY.** Windows runs of these tests, further junction/reparse/ACL and cross-process adversarial work, and crash-recovery verification are required before any security gate can be reconsidered.

## SA-02 — adversarial test compile fix (2026-10-16)

The first Windows Release run after adding the two adversarial tests **did not execute either new test**: `FileSystemKeyStoreTests.cs` failed to compile at lines 829 and 893 (`CS0618`, obsolete NUnit `[Timeout]`; warnings are treated as errors). The independent unit suite still passed **296/296**. No integration TRX was produced by this run.

**Test-only correction:** both adversarial tests now use a local 30-second `CancellationTokenSource`. The token is passed to filesystem-store operations and awaited delays; racing tasks observe cancellation and are awaited together before their test directories are cleaned up. The obsolete NUnit timeout attributes were removed. This deadline is cooperative and does not forcibly abort synchronous filesystem calls.

**Not yet verified:** a Windows build and execution of the new tests following this correction. `SA-02` stays **OPEN / EXPERIMENTAL / TEST ONLY**; no claim about adversarial race resistance follows from a failed test compilation.

## SA-02 — Windows junction candidate (16 October 2026)

The latest verified Windows Release export recorded **369 tests: 355 passed, 0 failed, 14 platform skips** (296 unit tests and 59 integration tests). The existing Windows symbolic-link tests and two adversarial tests passed; this is evidence of test coverage, not a claim that every TOCTOU race is impossible.

**Next candidate, not yet built or executed:** three Windows-only adversarial NUnit tests now cover an NTFS mount-point junction used as the store root, a junction in an ancestor directory, and concurrent writes after a pinned root is renamed and its old path is replaced by a junction to an external sentinel directory. Junctions are created using Win32 `DeviceIoControl(FSCTL_SET_REPARSE_POINT)` on disposable directories; a missing reparse capability is explicitly *skipped*, not counted as passed. All outside sentinels and the target directory are checked for changes. No production store format or public API changes.

**EXPERIMENTAL / TEST ONLY; SA-02 OPEN.** Run Windows Release/NUnit and inspect the TRX for actual execution of all three new tests. Separate-process races, recovery under forced termination, Windows path mutation with alternate reparse tags, and Linux regression remain outstanding before security closeout. This does not change the Phase 27 NO-GO decision.

## SA-02 — verified Windows junction test run and interprocess race candidate (16 October 2026)

**Verified test evidence (user-supplied .trx / exporter ZIP, 19:13:36 +03:00):** Windows / .NET SDK 10.0.402 / Release reported **372 total: 358 passed, 0 failed, 14 platform skips**. Unit tests: **296/296**. Integration tests: **62 passed / 14 skipped** out of 76. The three new NTFS junction tests (`WindowsJunctionRootAliasIsRejected`, `WindowsJunctionInAncestorIsRejected`, `WindowsPinnedRootIgnoresReplacementJunctionDuringConcurrentWrites`) are present and passed. This replaces the earlier unverified candidate status *for those three tests only*.

**Next candidate — NOT YET BUILT OR RUN:** `WindowsExternalProcessJunctionSwapsCannotRedirectPinnedWrites` creates an independent `cmd.exe` adversary that repeatedly removes/recreates a disposable junction at the original directory pathname while the parent process uses a pre-opened, directory-handle-pinned store to perform 24 writes. A progress counter requires at least four junction installations before and after the write batch; the test verifies original entries, snapshot location, byte-for-byte sentinel integrity and absence of new files in the junction target. The worker touches only disposable test-generated paths, and cleanup stops it before restoring the renamed store directory. The test fixture is made `partial` solely to keep the extra adversarial case in a separate source file. No shipping library code, public APIs or serialized formats change.

**Limitations:** this bounded interprocess test does not prove immunity to all races, ACL attacks by the same Windows identity, every reparse-point type, rollback, crash durability, or cross-platform filesystem behavior. Success must be confirmed by a fresh Windows .trx; no conclusions should be drawn from an unexecuted candidate. **SA-02 remains OPEN; Windows backend EXPERIMENTAL / TEST ONLY; Phase 27 NO-GO for real secrets.**

## SA-02 — interprocess junction candidate compile correction (16 October 2026)

**Actual Windows Release evidence (export at 19:32:16 +03:00; .NET SDK 10.0.402):** the independent unit-test project passed **296/296**, but `Laveyana.Security.IntegrationTests` failed to compile and generated **no integration TRX**. The new `FileSystemKeyStoreTests.Interprocess.cs` contains an accidentally multiline C# string at lines 46–48. The compiler reported `CS1010`, `CS1003`, and `CS1026`. This is a test-source syntax error, **not a failed security assertion and not evidence that the interprocess race is safe**. All production dependencies compiled in this run. The last fully successful Windows run remains **358 passed, 0 failed, 14 platform skips** (19:13:36 +03:00).

**Test-only fix:** the generated CMD script is now converted to Windows CRLF line endings with an explicitly escaped C# expression: `ExternalProcessJunctionWorker.Replace("\n", "\r\n", StringComparison.Ordinal)`. No production code, public API, persisted format, or previous test logic was changed. This new correction is **not yet compiled or executed on Windows**; re-run the exporter and inspect the new integration TRX before claiming interprocess coverage.

**Status: SA-02 OPEN; Windows backend EXPERIMENTAL / TEST ONLY; Phase 27 NO-GO for production secrets.**


## SA-02 — consolidated Windows adversarial/recovery test batch (16 October 2026)

**Baseline verified by the user's Windows Release TRX (19:13:36 +03:00):** 372 tests total, **358 passed / 0 failed / 14 platform skips**; 296 unit and 62 executed integration tests. The subsequent independent-process junction test was *not* compiled successfully in the 19:32:16 report; the compiler failure (`CS1010`, `CS1003`, `CS1026`) came from its command-script string literal and is not a runtime security finding.

**This delivery is a candidate, not a verified test result.** It includes the corrected `FileSystemKeyStoreTests.Interprocess.cs`, with CRLF conversion of the raw CMD script and mandatory braces (IDE0011), plus **ten** additional Windows tests in `FileSystemKeyStoreTests.SecurityMatrix.cs`. Existing successful symlink, pinned-directory, concurrent-read/write and junction tests are preserved. No production filesystem code, public API, crypto format or lock policy was changed by this batch.

| New test | Security/recovery question addressed |
| --- | --- |
| `WindowsReopenRejectsJunctionAtReplacedRootWithoutTouchingDecoy` | New opens must reject a replaced junction, while an existing handle-bound store can still write only in the pinned directory. |
| `WindowsBootstrapSymlinkIsRejectedBeforeReadingTarget` | Bootstrap lookup must reject a file reparse point. |
| `WindowsPendingSymlinkIsNotFollowedOrRemovedAsOrdinaryStagedFile` | Recovery must not follow staged-file links, modify an external target, or silently accept the link. |
| `WindowsMultipleOrphanedPendingFilesAreRemovedAfterAuthentication` | Authenticated recovery removes multiple abandoned temporary files without altering committed data. |
| `WindowsCorruptSnapshotNeverTriggersPendingCleanup` | Invalid committed data prevents automatic recovery/cleanup and preserves diagnostic evidence. |
| `WindowsMissingCommittedSnapshotCannotBeReplacedByPendingCandidate` | A staged file is never promoted if the committed snapshot is missing. |
| `WindowsTruncatedCommittedSnapshotFailsClosedWithoutResettingBootstrap` | Truncated snapshot must fail without resetting bootstrap identity. |
| `WindowsExclusiveLockConflictWaitsThenTimesOutWithoutBypass` | Real Windows lock contention follows the bounded retry policy; there is no bypass. |
| `WindowsKilledExternalPendingWriterCannotAlterCommittedSnapshot` | Killing an independent CMD writer mid-staging leaves an orphan removed on authenticated restart; committed state remains unchanged. |
| `WindowsExternalProcessRemovingSnapshotIsDetectedWithoutAutoRecovery` | Deletion/move of the committed snapshot by another process causes fail-closed reads and reopening, not reset. |
| `WindowsExternalProcessJunctionSwapsCannotRedirectPinnedWrites` (prior candidate) | A separate CMD process repeatedly swaps junctions during pinned-root mutations. |

**Expected *if every candidate passes* (not yet observed):** 383 total, 369 passed, 0 failed, 14 Windows-inapplicable platform skips. A symlink privilege/environment skip would increase skips; every such skip must be reviewed, not counted as proof. These numbers assume unchanged original test inventory.

**Scope boundaries / unresolved risk:** `cmd.exe` killed while writing an *orphan staged file* is not a crash during `FileSystemKeyStore.CommitAsync` and is not a power-loss/durability test. Path-race tests are finite, not exhaustive. Real uncontrolled termination during library commit, multi-process cooperating writers, ACL changes during kernel operations, broader NT reparse classes, NTFS durability, Linux adversarial checks, and independent review are not completed. SA-03 rollback and SA-04 durable nonce protection remain separate HIGH/release gates. No tests claim to close SA-02 automatically.

**State: SA-02 OPEN; Windows filesystem backend EXPERIMENTAL / TEST ONLY; Phase 27 NO-GO for production secrets.** Await Windows build, all TRX outcomes and review of actual executed/skipped tests.

## SA-02 — consolidated test batch compile repair (16 October 2026, 19:51:50 +03:00)

**Observed Windows Release evidence from the user's ZIP** `DotNet-TestResults_2026-10-16_19-51-50.zip` (.NET SDK 10.0.402): `Laveyana.Security.Tests` built and all **296/296** unit tests passed. The integration-test project **did not compile** and therefore generated **no TRX**: `FileSystemKeyStoreTests.Interprocess.cs(30,9)` reports `CS0246` (unresolved `FileSystemKeyStore`). All referenced production projects successfully built. This report contains **no execution evidence** for the eleven new integration cases from the consolidated candidate. The last confirmed fully successful Windows test run remains **358 passed / 0 failed / 14 platform-skipped**.

**Source-only repair for the complete replacement package:** added `using Laveyana.Security.FileSystem.Storage;` to `FileSystemKeyStoreTests.Interprocess.cs` to resolve the production `FileSystemKeyStore` type. The full consolidated test set (the previously tested partial fixture, interprocess test, ten additional adversarial/recovery tests and the NTFS junction helper) is packaged together with this document and its Russian counterpart. No production code, public API or persistent on-disk format changed. File/namespace references, fixture declarations and the archive were inspected statically; **.NET 10 compilation and Windows execution remain unverified after this repair**.

Expected count *only if all candidates execute without skips or failures*: **383 total / 369 passed / 0 failed / 14 platform-skipped**. The integration suite may expose further test or product failures on first execution; do not interpret expected counts as confirmed outcomes. `SA-02` remains **OPEN / EXPERIMENTAL / TEST ONLY** and Phase 27 remains **NO-GO for production secrets**.

## SA-02 — consolidated Windows Release batch: observed verification (16 October 2026, 19:58:28 +03:00)

**Observed evidence (not a projection):** the user-supplied `DotNet-TestResults_2026-10-16_19-58-28.zip`, `Summary.txt`, two console logs and two TRX files. Windows, .NET SDK **10.0.402**, **Release**, `dotnet test` export. The .NET solution and both test projects built successfully.

| Test project | Passed | Failed | Platform skips | Total |
| --- | ---: | ---: | ---: | ---: |
| `Laveyana.Security.Tests` | 296 | 0 | 0 | 296 |
| `Laveyana.Security.IntegrationTests` | 73 | 0 | 14 | 87 |
| **Combined** | **369** | **0** | **14** | **383** |

**All eleven consolidated batch candidates really executed and passed** (not simply discovered): `WindowsReopenRejectsJunctionAtReplacedRootWithoutTouchingDecoy`, `WindowsBootstrapSymlinkIsRejectedBeforeReadingTarget`, `WindowsPendingSymlinkIsNotFollowedOrRemovedAsOrdinaryStagedFile`, `WindowsMultipleOrphanedPendingFilesAreRemovedAfterAuthentication`, `WindowsCorruptSnapshotNeverTriggersPendingCleanup`, `WindowsMissingCommittedSnapshotCannotBeReplacedByPendingCandidate`, `WindowsTruncatedCommittedSnapshotFailsClosedWithoutResettingBootstrap`, `WindowsExclusiveLockConflictWaitsThenTimesOutWithoutBypass`, `WindowsKilledExternalPendingWriterCannotAlterCommittedSnapshot`, `WindowsExternalProcessRemovingSnapshotIsDetectedWithoutAutoRecovery`, and `WindowsExternalProcessJunctionSwapsCannotRedirectPinnedWrites`. The external-process junction-swap test took approximately **8.31 seconds** and passed. All 14 skips correspond to test cases for other operating systems / unsupported platform conditions; no Windows junction or symlink security test in this batch was skipped.

**Interpretation:** the prior compile-only errors `CS1010`/`CS1003`/`CS1026` and `CS0246` are resolved for this Windows build. The finite test suite detected no regressions or violations in the tested scenarios. This confirms the test-batch outcome but **does not complete independent security assurance**: unbounded adversarial schedules, same-identity ACL changes, all NT reparse varieties, abrupt termination *inside* a committing library process, sudden loss of power, durable flushing, and Linux-specific adversarial testing are out of scope. In particular, termination of a helper process writing an orphan temporary file does not exercise kill-during-library-commit.

**Gate state remains unchanged:** **SA-02 OPEN for final manual threat-model/code review**; Windows filesystem backend **EXPERIMENTAL / TEST ONLY**, Phase 27 **NO-GO for real secrets**. SA-03 (rollback/replay) and SA-04 (persistent nonce safety) are separate unresolved release gates. The earlier historical candidate/test compile failures remain documented above as history, superseded by this observed successful run. No production code or additional tests are changed by this evidence-only update.
