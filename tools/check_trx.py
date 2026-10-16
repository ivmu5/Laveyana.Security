#!/usr/bin/env python3
"""Validate TRX test results and required OS-specific passed cases (not just discovery).

Run after dotnet test; checks that a required platform's tests really ran and passed.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

REQUIRED = {
    "Windows": (
        "RoundTripAcrossInstancesDoesNotMutateCallerLease",
        "WindowsRootRejectsUnexpectedReadGrant",
    ),
    "Linux": (
        "InsecureRootPermissionsAreRejectedWithoutRepair",
        "SymlinkInAncestorIsRejected",
    ),
}


def read_results(path: Path) -> list[tuple[str, str]]:
    doc = ET.parse(path)
    return [
        (item.get("testName", ""), item.get("outcome", ""))
        for item in doc.iter() if item.tag.rsplit("}", 1)[-1] == "UnitTestResult"
    ]


def check(files: list[Path], platform: str) -> list[str]:
    errors: list[str] = []
    if not files:
        return ["No TRX files produced. Test discovery or test execution may have failed."]
    results: list[tuple[str, str]] = []
    for file in files:
        try:
            records = read_results(file)
        except (OSError, ET.ParseError) as exc:
            errors.append(f"Cannot parse TRX {file}: {exc}")
            continue
        if not records:
            errors.append(f"TRX has no test results: {file}")
        else:
            passed = sum(status == "Passed" for _, status in records)
            failed = sum(status == "Failed" for _, status in records)
            skipped = len(records) - passed - failed
            print(f"{file.name}: passed={passed}, failed={failed}, other/skipped={skipped}")
        results.extend(records)

    if not any(status == "Passed" for _, status in results):
        errors.append("No tests actually passed.")
    bad = [(name, status) for name, status in results if status not in {"Passed", "NotExecuted", "Pending"}]
    if bad:
        errors.append(f"Non-success test outcomes: {bad[:10]}")
    for expected in REQUIRED[platform]:
        matching = [(n, outcome) for n, outcome in results if expected in n]
        if not matching:
            errors.append(f"Missing mandatory {platform} test: {expected}")
        elif not any(status == "Passed" for _, status in matching):
            errors.append(f"Mandatory {platform} test was not passed: {expected}: {matching}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("Windows", "Linux"), required=True)
    parser.add_argument("--results-dir", type=Path, required=True)
    args = parser.parse_args()
    files = sorted(args.results_dir.rglob("*.trx"))
    errors = check(files, args.platform)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"PASS: TRX discovery and mandatory {args.platform} platform tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
