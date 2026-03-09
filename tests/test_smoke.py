import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
AUDIT_CMD = [sys.executable, "-m", "security_code_audit"]


class AuditCliSmokeTests(unittest.TestCase):
    def run_audit(self, *args):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "report"
            cmd = [
                *AUDIT_CMD,
                *args,
                "--output",
                str(output_dir),
            ]
            result = subprocess.run(
                cmd,
                cwd=str(REPO_ROOT),
                env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
                capture_output=True,
                text=True,
                check=False,
            )
            report_path = output_dir / "audit-report.json"
            self.assertTrue(
                report_path.exists(),
                msg=f"Expected report file was not created.\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
            )
            sarif_path = output_dir / "audit-report.sarif"
            self.assertTrue(
                sarif_path.exists(),
                msg=f"Expected SARIF report file was not created.\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
            )
            with report_path.open("r", encoding="utf-8") as f:
                report = json.load(f)
            with sarif_path.open("r", encoding="utf-8") as f:
                sarif = json.load(f)
            return result, report, sarif, output_dir

    def run_audit_in_temp_project(self, files, *args):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir) / "project"
            project_root.mkdir()
            for relative_path, content in files.items():
                file_path = project_root / relative_path
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_text(content, encoding="utf-8")

            output_dir = project_root / "reports"
            cmd = [
                *AUDIT_CMD,
                *args,
                "--output",
                str(output_dir),
            ]
            result = subprocess.run(
                cmd,
                cwd=str(project_root),
                env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
                capture_output=True,
                text=True,
                check=False,
            )
            report_path = output_dir / "audit-report.json"
            self.assertTrue(
                report_path.exists(),
                msg=f"Expected report file was not created.\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
            )
            with report_path.open("r", encoding="utf-8") as f:
                report = json.load(f)
            return result, report, project_root

    def test_php_scan_produces_findings(self):
        result, report, sarif, _ = self.run_audit(
            "--path",
            "examples/php/vulnerable_app.php",
            "--language",
            "php",
            "--ruleset",
            "all",
        )
        self.assertIn(result.returncode, {1, 2})
        self.assertEqual(report["scan_info"]["language"], "php")
        self.assertIn("scan_basis", report["scan_info"])
        self.assertNotIn("rules_loaded", report["scan_info"])
        self.assertGreater(report["summary"]["total_findings"], 0)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertGreater(len(sarif["runs"][0]["results"]), 0)

    def test_csharp_scan_produces_findings(self):
        result, report, _, _ = self.run_audit(
            "--path",
            "examples/csharp/VulnerableController.cs",
            "--language",
            "csharp",
            "--ruleset",
            "all",
        )
        self.assertIn(result.returncode, {1, 2})
        self.assertEqual(report["scan_info"]["language"], "csharp")
        self.assertGreater(report["summary"]["total_findings"], 0)

    def test_kotlin_scan_produces_findings(self):
        result, report, _, _ = self.run_audit(
            "--path",
            "examples/kotlin/VulnerableController.kt",
            "--language",
            "kotlin",
            "--ruleset",
            "all",
        )
        self.assertIn(result.returncode, {1, 2})
        self.assertEqual(report["scan_info"]["language"], "kotlin")
        self.assertGreater(report["summary"]["total_findings"], 0)

    def test_changed_files_limits_scan_scope(self):
        result, report, sarif, _ = self.run_audit(
            "--path",
            "examples",
            "--language",
            "php",
            "--ruleset",
            "all",
            "--changed-files",
            "examples/php/vulnerable_app.php",
        )
        self.assertIn(result.returncode, {1, 2})
        self.assertEqual(report["scan_info"]["scan_scope"], "changed")
        self.assertEqual(report["scan_info"]["total_files"], 1)
        self.assertGreater(report["summary"]["total_findings"], 0)
        self.assertEqual(sarif["runs"][0]["automationDetails"]["id"], "php-changed-all")

    def test_toml_config_sets_defaults(self):
        files = {
            ".security-audit.toml": '\n'.join([
                'path = "."',
                'language = "php"',
                'ruleset = "all"',
                'confidence = "low"',
            ]),
            "vulnerable.php": '\n'.join([
                '<?php',
                '$name = $_GET["name"];',
                '$query = "SELECT * FROM users WHERE name = \'" . $name . "\'";',
            ]),
        }
        result, report, _ = self.run_audit_in_temp_project(
            files,
        )
        self.assertIn(result.returncode, {1, 2})
        self.assertEqual(report["scan_info"]["language"], "php")

    def test_inline_suppression_skips_finding(self):
        files = {
            "suppressed.php": '\n'.join([
                '<?php',
                '$name = $_GET["name"];',
                '// security-code-audit: ignore sqli-001',
                '$query = "SELECT * FROM users WHERE name = \'" . $name . "\'";',
            ]),
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir) / "project"
            project_root.mkdir()
            file_path = project_root / "suppressed.php"
            file_path.write_text(files["suppressed.php"], encoding="utf-8")
            output_dir = project_root / "reports"
            cmd = [
                *AUDIT_CMD,
                "--path",
                str(file_path),
                "--language",
                "php",
                "--ruleset",
                "all",
                "--output",
                str(output_dir),
            ]
            result = subprocess.run(
                cmd,
                cwd=str(project_root),
                env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0)
            report = json.loads((output_dir / "audit-report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["total_findings"], 0)

    def test_skill_mode_returns_zero_and_generates_ai_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "report"
            cmd = [
                *AUDIT_CMD,
                "--path",
                "examples/php/vulnerable_app.php",
                "--language",
                "php",
                "--ruleset",
                "all",
                "--skill-mode",
                "--output",
                str(output_dir),
            ]
            result = subprocess.run(
                cmd,
                cwd=str(REPO_ROOT),
                env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0)
            self.assertTrue((output_dir / "audit-report-ai.md").exists())
            self.assertTrue((output_dir / "ai-analysis-prompt.txt").exists())
            report = json.loads((output_dir / "audit-report.json").read_text(encoding="utf-8"))
            self.assertTrue(report["scan_info"]["skill_mode"])
            self.assertGreater(report["summary"]["total_findings"], 0)

    def test_skill_mode_generates_ai_report_for_zero_findings(self):
        files = {
            "safe.php": '\n'.join([
                '<?php',
                'function greet(string $name): string {',
                '    return "Hello, " . $name;',
                '}',
            ]),
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir) / "project"
            project_root.mkdir()
            file_path = project_root / "safe.php"
            file_path.write_text(files["safe.php"], encoding="utf-8")
            output_dir = project_root / "reports"
            cmd = [
                *AUDIT_CMD,
                "--path",
                str(file_path),
                "--language",
                "php",
                "--ruleset",
                "all",
                "--skill-mode",
                "--output",
                str(output_dir),
            ]
            result = subprocess.run(
                cmd,
                cwd=str(project_root),
                env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("AI review: completed", result.stdout)
            self.assertTrue((output_dir / "audit-report-ai.md").exists())
            ai_report = (output_dir / "audit-report-ai.md").read_text(encoding="utf-8")
            self.assertIn("未发现命中的安全漏洞规则", ai_report)


if __name__ == "__main__":
    unittest.main()
