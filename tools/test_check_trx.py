#!/usr/bin/env python3
"""Standard-library regression tests for the TRX CI evidence gate.

Run: python tools/test_check_trx.py
No NUnit, .NET SDK, or external packages are required.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import xml.etree.ElementTree as ET

import check_trx


class TrxValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)

    def _write(self, suite: str, names: list[str], outcomes: dict[str, str] | None = None,
               *, filename: str | None = None) -> Path:
        root = ET.Element("TestRun")
        definitions = ET.SubElement(root, "TestDefinitions")
        results = ET.SubElement(root, "Results")
        for index, qualified in enumerate(names, start=1):
            klass, name = qualified.split(".", 1)
            test = ET.SubElement(definitions, "UnitTest", id=f"id-{index}", name=name)
            ET.SubElement(test, "TestMethod", className=suite + "." + klass,
                          name=name, codeBase=f"/run/{suite}.dll")
            ET.SubElement(results, "UnitTestResult", testId=f"id-{index}",
                          testName=name, outcome=(outcomes or {}).get(qualified, "Passed"))
        count_passed = sum((outcomes or {}).get(n, "Passed") == "Passed" for n in names)
        summary = ET.SubElement(root, "ResultSummary")
        ET.SubElement(summary, "Counters", total=str(len(names)), passed=str(count_passed))
        filename = filename or ("unit.trx" if suite == check_trx.UNIT else "integration.trx")
        target = self.root / filename
        ET.ElementTree(root).write(target, encoding="utf-8", xml_declaration=True)
        return target

    def _fixture(self, platform: str) -> list[Path]:
        unit = list(check_trx.REQUIRED_UNIT)
        integration = list(check_trx.REQUIRED_INTEGRATION + check_trx.REQUIRED_PLATFORM[platform])
        # Test that ordinary platform skips do not fail unrelated required cases.
        integration.append("FileSystemKeyStoreTests.OptionalOppositeOsCase")
        return [self._write(check_trx.UNIT, unit),
                self._write(check_trx.INTEGRATION, integration,
                            {"FileSystemKeyStoreTests.OptionalOppositeOsCase": "NotExecuted"})]

    @staticmethod
    def _check(files: list[Path], platform: str) -> list[str]:
        with redirect_stdout(StringIO()):
            return check_trx.check(files, platform)

    def test_accepts_complete_windows_and_linux_runs(self) -> None:
        for platform in ("Windows", "Linux"):
            with self.subTest(platform=platform):
                self.assertEqual([], self._check(self._fixture(platform), platform))

    def test_rejects_missing_required_platform_regression(self) -> None:
        files = self._fixture("Windows")
        missing = check_trx.REQUIRED_PLATFORM["Windows"][1]
        names = [x for x in check_trx.REQUIRED_INTEGRATION + check_trx.REQUIRED_PLATFORM["Windows"]
                 if x != missing]
        self._write(check_trx.INTEGRATION, names)
        self.assertIn("missing", " ".join(self._check(files, "Windows")))

    def test_rejects_skipped_required_linux_regression(self) -> None:
        files = self._fixture("Linux")
        name = check_trx.REQUIRED_PLATFORM["Linux"][-1]
        names = list(check_trx.REQUIRED_INTEGRATION + check_trx.REQUIRED_PLATFORM["Linux"])
        self._write(check_trx.INTEGRATION, names, {name: "NotExecuted"})
        self.assertIn(name, " ".join(self._check(files, "Linux")))

    def test_rejects_skipped_required_unit_regression(self) -> None:
        files = self._fixture("Windows")
        name = check_trx.REQUIRED_UNIT[0]
        self._write(check_trx.UNIT, list(check_trx.REQUIRED_UNIT), {name: "NotExecuted"})
        self.assertIn(name, " ".join(self._check(files, "Windows")))

    def test_rejects_wrong_method_name_containing_expected_substring(self) -> None:
        files = self._fixture("Windows")
        required = check_trx.REQUIRED_PLATFORM["Windows"][0]
        names = [x + "Extra" if x == required else x
                 for x in check_trx.REQUIRED_INTEGRATION + check_trx.REQUIRED_PLATFORM["Windows"]]
        self._write(check_trx.INTEGRATION, names)
        self.assertIn(required + ": missing", " ".join(self._check(files, "Windows")))

    def test_rejects_missing_one_real_writer_crash_boundary(self) -> None:
        files = self._fixture("Linux")
        required = 'FileSystemKeyStoreTests.KilledLibraryWriterReopensOneAuthenticatedSnapshot("AfterRename",True)'
        names = [n for n in check_trx.REQUIRED_INTEGRATION + check_trx.REQUIRED_PLATFORM["Linux"] if n != required]
        self._write(check_trx.INTEGRATION, names)
        self.assertIn(required + ": missing", " ".join(self._check(files, "Linux")))

    def test_rejects_skipped_nonce_history_guard(self) -> None:
        files = self._fixture("Windows")
        required = "SoftwareNonceLifetimeTests.ReopenedBackendRejectsForwardEncryptionButCanDecryptAndExplicitlyRotate"
        self._write(check_trx.UNIT, list(check_trx.REQUIRED_UNIT), {required: "NotExecuted"})
        self.assertIn(required, " ".join(self._check(files, "Windows")))

    def test_rejects_single_suite(self) -> None:
        files = self._fixture("Windows")
        self.assertIn("exactly one", " ".join(self._check(files[:1], "Windows")))

    def test_rejects_duplicate_trx_for_one_suite(self) -> None:
        files = self._fixture("Windows")
        duplicate = self._write(check_trx.UNIT, list(check_trx.REQUIRED_UNIT), filename="old.trx")
        errors = self._check(files + [duplicate], "Windows")
        self.assertTrue(any("exactly two TRX" in e for e in errors))
        self.assertTrue(any("Duplicate test result" in e for e in errors))

    def test_rejects_malformed_xml(self) -> None:
        files = self._fixture("Windows")
        files[0].write_text("not xml", encoding="utf-8")
        self.assertIn("Cannot validate", " ".join(self._check(files, "Windows")))

    def test_rejects_failed_or_pending_test(self) -> None:
        for outcome in ("Failed", "Pending", "Aborted"):
            with self.subTest(outcome=outcome):
                files = self._fixture("Windows")
                self._write(check_trx.UNIT, list(check_trx.REQUIRED_UNIT),
                            {check_trx.REQUIRED_UNIT[0]: outcome})
                self.assertIn("Non-success", " ".join(self._check(files, "Windows")))

    def test_rejects_fake_assembly_identity(self) -> None:
        files = self._fixture("Windows")
        doc = ET.parse(files[0])
        method = doc.find("./TestDefinitions/UnitTest/TestMethod")
        assert method is not None
        method.set("codeBase", "/run/WrongProject.dll")
        doc.write(files[0], encoding="utf-8")
        self.assertIn("mismatched assembly", " ".join(self._check(files, "Windows")))

    def test_rejects_inconsistent_summary(self) -> None:
        files = self._fixture("Windows")
        doc = ET.parse(files[1])
        counters = doc.find("./ResultSummary/Counters")
        assert counters is not None
        counters.set("passed", "999")
        doc.write(files[1], encoding="utf-8")
        self.assertIn("Counter passed", " ".join(self._check(files, "Windows")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
