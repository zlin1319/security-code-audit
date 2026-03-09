import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from security_code_audit.audit import SecurityAuditor

RULE_CASES = {
    "sqli-001": {
        "language": "php",
        "positive": '\n'.join([
            '<?php',
            '$name = $_GET["name"];',
            '$query = "SELECT * FROM users WHERE name = \'" . $_GET["name"];',
        ]),
        "negative": '\n'.join([
            '<?php',
            '$stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");',
            '$stmt->execute([$name]);',
        ]),
    },
    "xss-001": {
        "language": "php",
        "positive": '\n'.join([
            '<?php',
            'echo "<div>" . $_GET["name"];',
        ]),
        "negative": '\n'.join([
            '<?php',
            'echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");',
        ]),
    },
    "cmdi-001": {
        "language": "php",
        "positive": '\n'.join([
            '<?php',
            'system($_GET["cmd"]);',
        ]),
        "negative": '\n'.join([
            '<?php',
            '$allowed = ["status"];',
            'if (in_array($cmd, $allowed, true)) { echo $cmd; }',
        ]),
    },
    "pathtraversal-001": {
        "language": "php",
        "positive": '\n'.join([
            '<?php',
            'readfile($_GET["path"]);',
        ]),
        "negative": '\n'.join([
            '<?php',
            '$base = "/srv/files/";',
            '$safe = $base . basename($name);',
            'readfile($safe);',
        ]),
    },
    "deserialization-001": {
        "language": "php",
        "positive": '\n'.join([
            '<?php',
            'unserialize($_GET["payload"]);',
        ]),
        "negative": '\n'.join([
            '<?php',
            '$data = json_decode($payload, true);',
        ]),
    },
    "ssrf-001": {
        "language": "php",
        "positive": '\n'.join([
            '<?php',
            'file_get_contents($_GET["url"]);',
        ]),
        "negative": '\n'.join([
            '<?php',
            '$allowed = ["https://api.example.com/users"];',
            '$body = file_get_contents($allowed[0]);',
        ]),
    },
    "crypto-001": {
        "language": "php",
        "positive": '\n'.join([
            '<?php',
            '$hash = md5($password);',
        ]),
        "negative": '\n'.join([
            '<?php',
            '$hash = password_hash($password, PASSWORD_BCRYPT);',
        ]),
    },
    "crypto-002": {
        "language": "php",
        "positive": '\n'.join([
            '<?php',
            '$cipher = openssl_encrypt($data, "des-ede3", $key, 0, $iv);',
        ]),
        "negative": '\n'.join([
            '<?php',
            '$cipher = openssl_encrypt($data, "aes-256-cbc", $key, 0, $iv);',
        ]),
    },
    "crypto-003": {
        "language": "php",
        "positive": '\n'.join([
            '<?php',
            '$value = mt_rand();',
        ]),
        "negative": '\n'.join([
            '<?php',
            '$value = random_int(1, 1000);',
        ]),
    },
    "infoleak-001": {
        "language": "php",
        "positive": '\n'.join([
            '<?php',
            '$password = "hardcoded-secret";',
        ]),
        "negative": '\n'.join([
            '<?php',
            '$message = "hello";',
            'echo $message;',
        ]),
    },
}


class RuleBaselineTests(unittest.TestCase):
    def _scan_source(self, language: str, filename: str, source: str):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / filename
            target.write_text(source, encoding="utf-8")

            auditor = SecurityAuditor(
                target_path=str(target),
                language=language,
                ruleset="all",
                output_dir=str(root / "reports"),
                confidence_threshold="low",
            )
            with redirect_stdout(StringIO()):
                report = auditor.run()
            return {finding["rule_id"] for finding in report["findings"]}

    def test_each_rule_has_positive_and_negative_baseline(self):
        for rule_id, case in RULE_CASES.items():
            with self.subTest(rule_id=rule_id, expectation="positive"):
                findings = self._scan_source(case["language"], f"{rule_id}.php", case["positive"])
                self.assertIn(rule_id, findings)

            with self.subTest(rule_id=rule_id, expectation="negative"):
                findings = self._scan_source(case["language"], f"{rule_id}-safe.php", case["negative"])
                self.assertNotIn(rule_id, findings)


if __name__ == "__main__":
    unittest.main()
