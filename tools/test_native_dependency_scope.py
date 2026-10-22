#!/usr/bin/env python3
"""Regressions for native build scope discovery (CI-01/02/03)."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from native_dependency_scope import changed_paths, is_shared_build_input, native_scope


class NativeDependencyScopeTests(unittest.TestCase):
    def test_docs_only_skips_both_native_platforms(self) -> None:
        self.assertEqual(native_scope(["docs/guide.md"]), {"android": False, "apple": False})

    def test_platform_only_runs_its_platform(self) -> None:
        self.assertEqual(native_scope(["platforms/android/README.md"]), {"android": True, "apple": False})
        self.assertEqual(native_scope(["platforms/apple/README.md"]), {"android": False, "apple": True})

    def test_shared_native_sources_run_both(self) -> None:
        for path in (
            "src/Laveyana.Security.Maui/NativeKeys/INativeSigningKeyService.cs",
            "src/Laveyana.Security.Abstractions/Identifiers/KeyId.cs",
            "tests/Laveyana.Security.Tests/Maui/NativeSigningKeyContractTests.cs",
            "tools/native_dependency_scope.py",
            ".github/workflows/verify.yml",
        ):
            with self.subTest(path=path):
                self.assertEqual(native_scope([path]), {"android": True, "apple": True})

    def test_config_and_new_nested_msbuild_inputs_are_global(self) -> None:
        for path in (
            ".editorconfig",
            "Directory.Build.targets",
            "src/Directory.Build.targets",
            "Directory.Build.props",
            "global.json",
            "NuGet.Config",
            "nested/nuget.config",
            "nested/build.rsp",
            "nested/rules.ruleset",
            "build/analysis.globalconfig",
            "tests/Laveyana.Security.Tests/Laveyana.Security.Tests.csproj",
            "Directory.Packages.props",
            "platforms/any/ReviewProbe.csproj",
            ".nuget/NuGet.Config",
            "platforms/android/packages.lock.json",
        ):
            with self.subTest(path=path):
                self.assertTrue(is_shared_build_input(path), path)

    def test_nonbuild_files_not_global(self) -> None:
        for path in ("README.md", "docs/README.ru.md", "src/Laveyana.Security/Primitives/LocalCryptography.cs"):
            with self.subTest(path=path):
                self.assertFalse(is_shared_build_input(path))

    def test_special_unicode_and_embedded_newline_paths_from_real_git_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def git(*args: str) -> str:
                return subprocess.check_output(["git", *args], cwd=root, text=True).strip()
            git("init", "-q")
            git("config", "user.name", "CI fixture")
            git("config", "user.email", "ci-fixture@example.invalid")
            (root / "README.md").write_text("base\n", encoding="utf-8")
            git("add", "-A")
            git("commit", "-qm", "baseline")
            base = git("rev-parse", "HEAD")
            unusual = [
                "platforms/android/ReviewProbe.é.cs",
                "platforms/apple/ReviewProbe.é.cs",
                "platforms/android/line\nbreak.cs",
                'platforms/apple/quote"literal.cs',
            ]
            for file in unusual:
                p = root / file
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("#error Expected native compile failure\n", encoding="utf-8")
            git("add", "-A")
            git("commit", "-qm", "unicode paths")
            head = git("rev-parse", "HEAD")
            old = Path.cwd()
            import os
            try:
                os.chdir(root)
                actual = changed_paths(base, head)
            finally:
                os.chdir(old)
            self.assertEqual(set(actual), set(unusual))
            self.assertEqual(native_scope(actual), {"android": True, "apple": True})

    def test_force_all(self) -> None:
        self.assertEqual(native_scope([], force_all=True), {"android": True, "apple": True})


if __name__ == "__main__":
    unittest.main()
