#!/usr/bin/env python3
"""Classify changes affecting native Android/Apple builds in required Verify CI.

Git diff pathnames are NUL-delimited to avoid Git's C-quoting of Unicode,
whitespace, backslashes and embedded newlines. This module deliberately
over-classifies build configuration files: an unnecessary native compile
is preferable to a silently skipped required platform check.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterable

PLATFORMS = ("android", "apple")
COMMON_PREFIXES = (
    "src/Laveyana.Security.Maui/",
    "src/Laveyana.Security.Abstractions/",
    "tests/Laveyana.Security.Tests/Maui/",
)
ALL_NATIVE_EXACT = {
    "global.json",
    ".github/workflows/verify.yml",
    "tools/native_dependency_scope.py",
    "tools/test_native_dependency_scope.py",
}
# Includes newly added/nested MSBuild/analysis configuration inputs, not
# merely a hard-coded list of root Directory.Build.props file names.
BUILD_SUFFIXES = (
    ".props",
    ".targets",
    ".rsp",
    ".editorconfig",
    ".globalconfig",
    ".ruleset",
    ".csproj",
    ".sln",
    ".slnx",
    ".nuspec",
)


def changed_paths(base: str, head: str) -> tuple[str, ...]:
    """Get changed old/new names; no renames, no C-quoting, no line splitting."""
    raw = subprocess.check_output(
        ["git", "diff", "--no-renames", "--name-only", "-z", base, head]
    )
    if raw and not raw.endswith(b"\0"):
        raise ValueError("Unexpected non-NUL-terminated git diff output.")
    return tuple(os.fsdecode(part) for part in raw.split(b"\0") if part)


def is_shared_build_input(path: str) -> bool:
    normalized = path.lower()
    basename = normalized.rsplit("/", 1)[-1]
    if path in ALL_NATIVE_EXACT or path.startswith(COMMON_PREFIXES):
        return True
    if normalized.startswith(".nuget/") or basename in ("nuget.config", "global.json"):
        return True
    if normalized.endswith(BUILD_SUFFIXES) or basename == "packages.lock.json":
        return True
    return False


def native_scope(paths: Iterable[str], *, force_all: bool = False) -> dict[str, bool]:
    if force_all:
        return {platform: True for platform in PLATFORMS}
    names = tuple(paths)
    return {
        platform: any(
            is_shared_build_input(name)
            or name.startswith(f"platforms/{platform}/")
            or name == f".github/workflows/{platform}-native.yml"
            for name in names
        )
        for platform in PLATFORMS
    }


def main() -> None:
    event = os.environ["EVENT"]
    base = os.environ.get("BASE_SHA", "")
    head = os.environ.get("HEAD_SHA", "")
    force_all = event == "workflow_dispatch" or not base or base == "0" * 40
    scope = native_scope(() if force_all else changed_paths(base, head), force_all=force_all)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        for platform, needed in scope.items():
            value = "true" if needed else "false"
            output.write(f"{platform}={value}\n")
            print(f"{platform}: {value}")


if __name__ == "__main__":
    main()
