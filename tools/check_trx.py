#!/usr/bin/env python3
"""Fail closed when NUnit TRX evidence omits required platform/security tests.

CI supplies one results directory per complete attempt, containing exactly one
unit TRX and one integration TRX. A TRX outcome is evidence of execution only;
this validator does not replace a successful dotnet test exit status.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

UNIT = "Laveyana.Security.Tests"
INTEGRATION = "Laveyana.Security.IntegrationTests"
SUITES = (UNIT, INTEGRATION)

# Keep this list intentionally small and security-relevant. Add newly accepted
# regressions here explicitly: incidental discovery is not an execution gate.
REQUIRED_UNIT = (
    "RollbackAuthorityContractTests.CheckpointOwnsItsDigestAndDoesNotExposeMutableBackingStorage",
    "RollbackAuthorityContractTests.CheckpointRejectsUndefinedIdentitySequenceAndWrongDigestLength",
    "RollbackAuthorityContractTests.PendingStateRequiresExactNextSequenceAndMatchingIdentity",
    "RollbackAuthorityContractTests.DigestBindsExactBytesStoreIdentityAndCommitSequence",
    "RollbackAuthorityContractTests.ExactCommittedSnapshotIsReadableOnlyWithoutPendingIntent",
    "RollbackAuthorityContractTests.PreparedStateRejectsOldFileAndBlocksNewFileUntilFinalized",
    "RollbackAuthorityContractTests.SimulatedCrashAfterPrepareMustRemainUnavailableForReads",
    "RollbackAuthorityContractTests.SimulatedProtocolRejectsConflictingPreparesAndHistoricalReplay",
    "RollbackAuthorityContractTests.OldAuthenticatedSnapshotIsRejectedAfterNewerCheckpointCommitted",
    "RollbackAuthorityContractTests.ContractLivesInAbstractionsAndCannotBeConfusedWithNonceAuthority",
    "RollbackRequestAuthorityContractTests.DelayedPrepareCannotApplyAfterUnknownRequestWasDurablyFenced",
    "RollbackRequestAuthorityContractTests.UnknownRequestIsUnresolvedWhenAuthorityCannotFenceIt",
    "RollbackRequestAuthorityContractTests.LostPrepareReplyIsResolvedFromTheOriginalRequestWithoutAnotherMutation",
    "RollbackRequestAuthorityContractTests.FinalizationResolutionRemainsAppliedAfterTheStoreAdvances",
    "RollbackRequestAuthorityContractTests.DelayedEnrollmentIsRejectedAfterResolutionFence",
    "RollbackRequestAuthorityContractTests.DelayedFinalizeCannotAdvanceAfterRequestWasFenced",
    "RollbackRequestAuthorityContractTests.ConcurrentDuplicatePrepareRequestsShareExactlyOneDecision",
    "SecurityObservabilityTests.BrokenDiagnosticsNeverRewriteOperationResults",
    "SecurityObservabilityTests.ThrowingSamplerDoesNotPreventActionOrChangeItsException",
    "SecurityObservabilityTests.ThrowingActivityStartedDoesNotLeakAmbientTraceOrRerunAction",
    "SecurityObservabilityTests.ThrowingActivityStoppedCannotReplaceCommittedResultOrOriginalFailure",
    "SecurityObservabilityTests.ThrowingStopListenerCannotChangeRealCommittedKeyCreation",
)

REQUIRED_INTEGRATION = (
    "FileSystemKeyStoreTests.HistoricalSnapshotReplayCannotBeDetectedWithoutExternalRollbackAuthority",
    "FileSystemKeyStoreTests.ReadOnlyOpenPreservesPendingFilesAndCommittedStoreBytes",
    "FileSystemKeyStoreTests.ReadOnlyOpenDoesNotCleanPendingFilesWhenSnapshotIsInvalid",
    "FileSystemKeyStoreTests.CorruptSnapshotNeverRecreatesOrUsesUnauthenticatedState",
    "FileSystemKeyStoreTests.RollbackReadGateAcceptsExactAuthenticatedCommittedSnapshot",
    "FileSystemKeyStoreTests.RollbackReadGateRejectsReplayedValidOldSnapshot",
    "FileSystemKeyStoreTests.RollbackReadGateRejectsBothPendingOldAndPendingNewSnapshot",
    "FileSystemKeyStoreTests.RollbackCandidateJournalPersistsExactSnapshotAndTwoStableRequestIds",
    "FileSystemKeyStoreTests.RollbackCandidateJournalRejectsTamperedAuthenticatedIntent",
    "FileSystemKeyStoreTests.RollbackCandidateJournalFailsClosedOnPartialStageAndKeepsEvidence",
    "FileSystemKeyStoreTests.RollbackRecoveryInspectorRejectsActiveRollbackAndUnexpectedPublication",
    "FileSystemKeyStoreTests.RollbackRecoveryInspectorRejectsMissingForeignOrConflictingAuthorityState",
    "FileSystemKeyStoreTests.RollbackRecoveryInspectorReadsAuthenticatedStageWithoutChangingAnyFiles",
)

REQUIRED_PLATFORM = {
    "Windows": (
        "FileSystemKeyStoreTests.WindowsRootRejectsUnexpectedReadGrant",
        "FileSystemKeyStoreTests.WindowsExternalProcessJunctionSwapsCannotRedirectPinnedWrites",
        "FileSystemKeyStoreTests.WindowsPinnedRenameAndConcurrentDisposeKeepExactlyOneValidCopy",
        "FileSystemKeyStoreTests.WindowsPinnedEnumerateAndConcurrentDisposeNeverReturnMalformedEntries",
        "FileSystemKeyStoreTests.WindowsPinnedOpenReadAndConcurrentDisposeNeverReturnInvalidStream",
        "FileSystemKeyStoreTests.WindowsPinnedRootIgnoresReplacementJunctionDuringConcurrentWrites",
        "FileSystemKeyStoreTests.WindowsReopenRejectsJunctionAtReplacedRootWithoutTouchingDecoy",
        "FileSystemKeyStoreTests.WindowsPendingSymlinkIsNotFollowedOrRemovedAsOrdinaryStagedFile",
        "FileSystemKeyStoreTests.WindowsCorruptSnapshotNeverTriggersPendingCleanup",
        "FileSystemKeyStoreTests.WindowsKilledExternalPendingWriterCannotAlterCommittedSnapshot",
    ),
    "Linux": (
        "FileSystemKeyStoreTests.InsecureRootPermissionsAreRejectedWithoutRepair",
        "FileSystemKeyStoreTests.SymlinkInAncestorIsRejected",
        "FileSystemKeyStoreTests.LinuxOpenDescriptorRemainsPinnedAfterPathRename",
        "LinuxSecureDirectoryLifetimeTests.LinuxOpenReadConcurrentDisposeKeepsReturnedStreamValid",
        "LinuxSecureDirectoryLifetimeTests.LinuxExistsConcurrentDisposeNeverUsesAnInvalidDirectoryDescriptor",
        "LinuxSecureDirectoryLifetimeTests.LinuxCreateTemporaryConcurrentDisposeNeverReturnsABrokenChildHandle",
        "LinuxSecureDirectoryLifetimeTests.LinuxLockConcurrentDisposeRetainsTheIndependentFlockHandle",
        "LinuxSecureDirectoryLifetimeTests.LinuxMoveConcurrentDisposePreservesExactlyOneCompleteFile",
        "LinuxSecureDirectoryLifetimeTests.LinuxOverwriteMoveConcurrentDisposePreservesOldOrNewSnapshot",
        "LinuxSecureDirectoryLifetimeTests.LinuxRemoveConcurrentDisposeCannotDeleteTheWrongFile",
        "LinuxSecureDirectoryLifetimeTests.LinuxDisposedDirectoryRejectsAllSubsequentNativeOperations",
        "LinuxSecureDirectoryLifetimeTests.LinuxPinnedRootConcurrentDisposeCannotWriteIntoReplacementDirectory",
    ),
}


@dataclass(frozen=True)
class Result:
    suite: str
    qualified_name: str
    outcome: str


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def child(parent: ET.Element, name: str) -> ET.Element | None:
    return next((x for x in parent if local_name(x.tag) == name), None)


def suite_for_class(class_name: str) -> str | None:
    return next((s for s in SUITES if class_name.startswith(s + ".")), None)


def read_results(path: Path) -> tuple[str, list[Result]]:
    """Parse one genuine VSTest TRX, including its test definitions and assembly."""
    root = ET.parse(path).getroot()
    if local_name(root.tag) != "TestRun":
        raise ValueError("TRX root must be TestRun")

    definitions = child(root, "TestDefinitions")
    results_element = child(root, "Results")
    if definitions is None or results_element is None:
        raise ValueError("Missing TRX TestDefinitions or Results")

    by_id: dict[str, tuple[str, str, str]] = {}
    for test in definitions:
        if local_name(test.tag) != "UnitTest":
            continue
        method = child(test, "TestMethod")
        if method is None:
            raise ValueError("UnitTest without TestMethod")
        test_id = test.get("id", "")
        class_name = method.get("className", "")
        name = method.get("name", "")
        suite = suite_for_class(class_name)
        if not test_id or not name or not suite or test_id in by_id:
            raise ValueError(f"Invalid/duplicate test definition: {test_id} {class_name}.{name}")
        # A forged class prefix in a testName is not accepted: identify the
        # originating test assembly from the NUnit TestMethod codeBase.
        assembly = method.get("codeBase", "").replace("\\", "/").rsplit("/", 1)[-1]
        if assembly.casefold() != (suite + ".dll").casefold():
            raise ValueError(f"Test definition has mismatched assembly: {class_name} / {assembly}")
        by_id[test_id] = (suite, class_name + "." + name, name)

    found: list[Result] = []
    for item in results_element:
        if local_name(item.tag) != "UnitTestResult":
            continue
        ref = by_id.get(item.get("testId", ""))
        if ref is None:
            raise ValueError(f"Result has unknown testId: {item.get('testId')}")
        suite, qualified_name, name = ref
        if item.get("testName") != name:
            raise ValueError(f"Result name mismatches TestMethod: {qualified_name}")
        outcome = item.get("outcome", "")
        if not outcome:
            raise ValueError(f"Result has no outcome: {qualified_name}")
        found.append(Result(suite, qualified_name, outcome))

    if not found:
        raise ValueError("TRX contains no UnitTestResult elements")
    suites = {r.suite for r in found}
    if len(suites) != 1:
        raise ValueError(f"One TRX must contain one test project, got {sorted(suites)}")

    # VSTest Counters.notExecuted does not necessarily count NUnit Ignored
    # results, so validate only total and passed when those counters exist.
    summary = child(root, "ResultSummary")
    counters = child(summary, "Counters") if summary is not None else None
    if counters is None:
        raise ValueError("Missing TRX ResultSummary/Counters")
    for attribute, actual in (("total", len(found)),
                              ("passed", sum(r.outcome == "Passed" for r in found))):
        try:
            reported = int(counters.attrib[attribute])
        except (KeyError, ValueError) as exc:
            raise ValueError(f"Missing or invalid counter {attribute}") from exc
        if reported != actual:
            raise ValueError(f"Counter {attribute}={reported} does not match results {actual}")

    return next(iter(suites)), found


def check(files: list[Path], platform: str) -> list[str]:
    if platform not in REQUIRED_PLATFORM:
        return [f"Unsupported platform: {platform}"]
    if not files:
        return ["No TRX files produced. Test discovery or execution may have failed."]

    errors: list[str] = []
    all_results: list[Result] = []
    file_suites: list[str] = []
    for path in files:
        try:
            suite, records = read_results(path)
        except (OSError, ET.ParseError, ValueError) as exc:
            errors.append(f"Cannot validate TRX {path}: {exc}")
            continue
        file_suites.append(suite)
        all_results.extend(records)
        counts = Counter(x.outcome for x in records)
        print(f"{path.name} [{suite}]: passed={counts['Passed']}, "
              f"not-executed={counts['NotExecuted']}, other={len(records) - counts['Passed'] - counts['NotExecuted']}")

    for suite in SUITES:
        count = file_suites.count(suite)
        if count != 1:
            errors.append(f"Expected exactly one {suite} TRX per attempt, found {count}")
    if len(files) != 2:
        errors.append(f"Expected exactly two TRX files per attempt, found {len(files)}; "
                      "use a fresh results directory for each CI run")

    seen: Counter[tuple[str, str]] = Counter((r.suite, r.qualified_name) for r in all_results)
    for (suite, name), count in seen.items():
        if count != 1:
            errors.append(f"Duplicate test result ({count}): {suite}: {name}")

    for result in all_results:
        if result.outcome not in {"Passed", "NotExecuted"}:
            errors.append(f"Non-success test outcome: {result.qualified_name}: {result.outcome}")

    expected_by_suite = {
        UNIT: REQUIRED_UNIT,
        INTEGRATION: REQUIRED_INTEGRATION + REQUIRED_PLATFORM[platform],
    }
    actual_by_suite = {(r.suite, r.qualified_name): r.outcome for r in all_results}
    for suite, names in expected_by_suite.items():
        for name in names:
            full_name = suite + "." + name
            status = actual_by_suite.get((suite, full_name))
            if status != "Passed":
                description = "missing" if status is None else status
                errors.append(f"Mandatory {platform} security test not Passed: {full_name}: {description}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=tuple(REQUIRED_PLATFORM), required=True)
    parser.add_argument("--results-dir", type=Path, required=True)
    args = parser.parse_args()
    errors = check(sorted(args.results_dir.rglob("*.trx")), args.platform)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"PASS: both NUnit suites and {args.platform} required security tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
