import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
SCRIPT = HERE / "security-scan.py"
VULNERABLE = HERE / "examples" / "vulnerable-app"
CLEAN = HERE / "examples" / "clean-app"

# the script name has a dash in it, so it can't be imported the normal way
spec = importlib.util.spec_from_file_location("security_scan", SCRIPT)
scan_module = importlib.util.module_from_spec(spec)
sys.modules["security_scan"] = scan_module
spec.loader.exec_module(scan_module)


def scan(path, *extra_args):
    """Run the script on a path with the built-in rules only and return (exit code, report)."""
    cmd = [sys.executable, str(SCRIPT), "--path", str(path), "--format", "json", "--builtin-only", *extra_args]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, json.loads(proc.stdout)


def write_and_scan(content, filename="a.py", *extra_args):
    with tempfile.TemporaryDirectory() as folder:
        (Path(folder) / filename).write_text(content)
        return scan(folder, *extra_args)


class DecisionTests(unittest.TestCase):
    def test_vulnerable_app_fails_in_every_category(self):
        code, report = scan(VULNERABLE)
        self.assertEqual(code, 1)
        self.assertEqual(report["decision"], "FAIL")
        categories = {f["category"] for f in report["findings"]}
        self.assertEqual(categories, {"sast", "dependency", "secrets", "iac"})

    def test_clean_app_passes(self):
        code, report = scan(CLEAN)
        self.assertEqual(code, 0)
        self.assertEqual(report["summary"]["total"], 0)

    def test_fail_on_threshold(self):
        medium_only = "import hashlib\nhashlib.md5(b'x')\n"
        self.assertEqual(write_and_scan(medium_only, "a.py", "--fail-on", "HIGH")[0], 0)
        self.assertEqual(write_and_scan(medium_only, "a.py", "--fail-on", "MEDIUM")[0], 1)

    def test_scanner_error_fails_the_run(self):
        broken = [scan_module.ScanResult("sast", "x", "error", detail="boom")]
        report = scan_module.build_report(Path("."), broken, "HIGH")
        self.assertEqual(report["decision"], "FAIL")


class RuleTests(unittest.TestCase):
    def test_inline_ignore_and_placeholders(self):
        code = 'x = eval(s)  # security-scan:ignore\napi_key = "your_api_key_here"\n'
        self.assertEqual(write_and_scan(code)[1]["summary"]["total"], 0)

    def test_method_calls_are_not_eval(self):
        code = "model.eval()\nre.exec(s)\ncursor.execute(q, p)\n"
        self.assertEqual(write_and_scan(code)[1]["summary"]["total"], 0)

    def test_secret_value_is_not_in_report(self):
        _, report = scan(VULNERABLE)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", json.dumps(report))


class InputTests(unittest.TestCase):
    def test_empty_folder_passes(self):
        with tempfile.TemporaryDirectory() as folder:
            code, report = scan(folder)
        self.assertEqual((code, report["summary"]["total"]), (0, 0))

    def test_single_file(self):
        code, report = scan(VULNERABLE / "app.py")
        self.assertEqual(code, 1)
        self.assertIn("app.py", {f["file"] for f in report["findings"]})

    def test_path_with_spaces(self):
        with tempfile.TemporaryDirectory() as folder:
            sub = Path(folder) / "my app"
            sub.mkdir()
            (sub / "a.py").write_text("eval(x)\n")
            self.assertEqual(scan(sub)[0], 1)

    def test_missing_path_exits_2(self):
        self.assertEqual(scan_module.main(["--path", "/does-not-exist"]), 2)

    def test_empty_scan_list_exits_2(self):
        self.assertEqual(scan_module.main(["--path", str(HERE), "--scans", ""]), 2)


class OutputTests(unittest.TestCase):
    def test_sarif(self):
        cmd = [sys.executable, str(SCRIPT), "--path", str(VULNERABLE), "--format", "sarif", "--builtin-only"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(json.loads(proc.stdout)["version"], "2.1.0")

    def test_scans_come_back_in_requested_order(self):
        _, report = scan(CLEAN, "--scans", "iac,secrets,sast")
        self.assertEqual([s["category"] for s in report["scans"]], ["iac", "secrets", "sast"])

    def test_report_has_schema_version_and_timestamp(self):
        _, report = scan(CLEAN)
        self.assertEqual(report["schema_version"], "1.0")
        self.assertIn("T", report["generated_at"])

    def test_cvss_to_severity(self):
        scores = ["9.8", "7.0", "5.3", "2.1", None, "n/a"]
        expected = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MEDIUM", "MEDIUM"]
        self.assertEqual([scan_module.cvss_to_severity(s) for s in scores], expected)


class MergeTests(unittest.TestCase):
    """run_scan() with fake engines, so no real tools are needed."""

    def with_engine(self, external, builtin):
        original = scan_module.ENGINES["secrets"]
        scan_module.ENGINES["secrets"] = ("python3", external, builtin)   # python3 is always on PATH
        try:
            return scan_module.run_scan("secrets", CLEAN, builtin_only=False)
        finally:
            scan_module.ENGINES["secrets"] = original

    def test_same_line_from_two_tools_keeps_the_more_severe(self):
        low = scan_module.Finding("secrets", "a", "R1", "LOW", "m", "f.py", 3)
        high = scan_module.Finding("secrets", "b", "R2", "CRITICAL", "m", "f.py", 3)
        result = self.with_engine(
            lambda root: scan_module.ScanResult("secrets", "a", "ok", findings=[low]),
            lambda root: scan_module.ScanResult("secrets", "b", "ok", findings=[high]))
        self.assertEqual([f.severity for f in result.findings], ["CRITICAL"])

    def test_external_tool_crash_is_reported_and_builtin_still_runs(self):
        def crash(root):
            raise RuntimeError("tool exploded", 2)

        result = self.with_engine(crash, scan_module.secrets_builtin)
        self.assertEqual(result.status, "ok")
        self.assertIn("tool exploded", result.detail)


class RequireToolsTests(unittest.TestCase):
    def run_with_binary(self, binary, require):
        original = scan_module.ENGINES["secrets"]
        scan_module.ENGINES["secrets"] = (binary, lambda root: scan_module.ScanResult("secrets", "fake", "ok"),
                                          scan_module.secrets_builtin)
        try:
            return scan_module.run_scan("secrets", CLEAN, builtin_only=False, require_tools=require)
        finally:
            scan_module.ENGINES["secrets"] = original

    def test_missing_tool_is_only_a_note_by_default(self):
        result = self.run_with_binary("no-such-scanner-xyz", require=False)
        self.assertEqual(result.status, "ok")
        self.assertIn("not installed", result.detail)

    def test_missing_tool_fails_when_required(self):
        result = self.run_with_binary("no-such-scanner-xyz", require=True)
        self.assertEqual(result.status, "error")
        report = scan_module.build_report(CLEAN, [result], "HIGH")
        self.assertEqual(report["decision"], "FAIL")

    def test_installed_tool_passes_when_required(self):
        self.assertEqual(self.run_with_binary("python3", require=True).status, "ok")

    def test_cannot_combine_with_builtin_only(self):
        with self.assertRaises(SystemExit):
            scan_module.main(["--path", str(CLEAN), "--require-tools", "--builtin-only"])


if __name__ == "__main__":
    unittest.main()
