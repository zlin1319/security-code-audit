#!/usr/bin/env python3
"""
Security Code Audit Tool
Performs static analysis for CWE Top 25 and OWASP Top 10 vulnerabilities.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

from .config_loader import load_config, merge_cli_with_config
from .context_analyzer import ContextAnalyzer
from .rules import (
    RULE_DEFINITIONS,
    SUPPORTED_LANGUAGES,
    get_active_cwes,
    get_extensions_for_language,
    get_patterns_for_language,
)
from .suppressions import (
    combine_patterns,
    is_finding_suppressed,
    load_ignore_patterns,
    should_ignore_path,
)

__version__ = "1.0.0"


class VulnerabilityRule:
    """Represents a security detection rule."""

    def __init__(self, rule_id: str, cwe: str, name: str, severity: str, patterns: dict[str, str]):
        self.rule_id = rule_id
        self.cwe = cwe
        self.name = name
        self.severity = severity
        self.patterns = patterns


class Finding:
    """Represents a security finding."""

    def __init__(
        self,
        rule: VulnerabilityRule,
        file: str,
        line_range: tuple[int, int],
        evidence: str,
        confidence: str,
        sink_source_summary: str | None = None,
    ):
        self.rule = rule
        self.file = file
        self.line_start = line_range[0]
        self.line_end = line_range[1]
        self.evidence_snippet = evidence
        self.confidence = confidence
        self.sink_source_summary = sink_source_summary or self._generate_summary()
        self.reasoning = self._generate_reasoning()
        self.fix_guidance = self._generate_fix_guidance()
        self.safe_fix_example = self._generate_safe_fix()
        # AI analysis fields
        self.ai_analysis = None
        self.ai_suggested_fix = None
        self.ai_is_false_positive = None

    def _generate_summary(self) -> str:
        """Generate sink/source taint summary."""
        summaries = {
            "sqli": "User input flows into SQL query construction without parameterization",
            "xss": "User-controlled data rendered in HTML context without encoding",
            "cmdi": "User input passed to shell command execution",
            "pathtraversal": "User-controlled path used in file operation without validation",
            "deserialization": "Untrusted data passed to deserialization function",
            "ssrf": "User-controlled URL used in server-side request",
            "auth": "Missing or weak authentication/authorization check",
            "infoleak": "Sensitive information potentially exposed",
            "crypto": "Weak cryptographic primitive used"
        }
        for key, summary in summaries.items():
            if key in self.rule.rule_id:
                return summary
        return "User input reaches sensitive sink"

    def _generate_reasoning(self) -> str:
        """Generate reasoning for why this is a vulnerability."""
        reasonings = {
            "sqli-001": "SQL injection occurs when untrusted user input is concatenated into SQL queries. Attackers can inject malicious SQL to bypass authentication, extract data, or modify database contents.",
            "xss-001": "Reflected XSS allows attackers to inject malicious scripts that execute in victims' browsers. This can lead to session hijacking, credential theft, or malware distribution.",
            "xss-002": "Stored XSS persists in the application database and affects all users viewing the content. It has higher impact than reflected XSS as it doesn't require social engineering.",
            "cmdi-001": "Command injection allows attackers to execute arbitrary system commands on the server, leading to full system compromise.",
            "pathtraversal-001": "Path traversal allows attackers to access files outside the intended directory, potentially exposing sensitive files like /etc/passwd or application configuration.",
            "deserialization-001": "Insecure deserialization can lead to remote code execution as attackers can craft malicious serialized objects that execute code during deserialization.",
            "ssrf-001": "SSRF allows attackers to make requests from the server to internal resources, potentially accessing internal APIs, metadata services, or performing port scanning.",
            "auth-001": "Weak authentication mechanisms can be bypassed or brute-forced, allowing unauthorized access to protected functionality.",
            "auth-002": "Missing authentication checks allow unauthenticated users to access protected resources or perform privileged operations.",
            "auth-003": "IDOR occurs when the application doesn't verify ownership of resources accessed via user-controlled identifiers, allowing access to other users' data.",
            "crypto-001": "Weak hashing algorithms like MD5 or SHA1 are vulnerable to collision attacks and rainbow table attacks, making password cracking feasible.",
            "crypto-002": "Weak encryption algorithms provide insufficient protection and can be decrypted by determined attackers.",
            "crypto-003": "Insecure random number generation can lead to predictable tokens, session IDs, or cryptographic keys."
        }
        return reasonings.get(self.rule.rule_id, f"This {self.rule.name} vulnerability can be exploited by attackers to compromise application security.")

    def _generate_fix_guidance(self) -> str:
        """Generate fix guidance."""
        guidance = {
            "sqli-001": "Use parameterized queries (prepared statements) for all database interactions. Never concatenate user input into SQL strings. Use an ORM if possible.",
            "xss-001": "Contextually encode all user input before rendering in HTML. Use auto-escaping template engines. Implement Content-Security-Policy headers.",
            "xss-002": "Same as reflected XSS. Additionally, sanitize stored content if HTML is allowed using a whitelist-based sanitizer like DOMPurify.",
            "cmdi-001": "Avoid shell command execution with user input. Use parameterized APIs if available. If necessary, strictly validate/allowlist input and avoid shell interpretation.",
            "pathtraversal-001": "Validate and sanitize file paths. Use allowlists of allowed filenames. Resolve canonical paths and verify they remain within intended directories.",
            "deserialization-001": "Avoid deserializing untrusted data. Use JSON with validation instead. If serialization is required, implement integrity checks and type constraints.",
            "ssrf-001": "Implement URL allowlists. Disable redirects or validate redirect targets. Use internal services instead of making external requests for internal operations.",
            "auth-001": "Implement strong password policies. Use multi-factor authentication. Implement account lockout mechanisms. Use secure session management.",
            "auth-002": "Add authentication checks to all protected endpoints. Use framework-provided security annotations or middleware. Centralize authentication logic.",
            "auth-003": "Verify resource ownership before access. Use indirect reference maps. Implement authorization checks at the data layer, not just UI layer.",
            "crypto-001": "Use strong hashing algorithms like bcrypt, Argon2, or scrypt for passwords. These are designed to be slow and resistant to brute force.",
            "crypto-002": "Use AES-256-GCM or ChaCha20-Poly1305 for encryption. Use well-established cryptographic libraries, never roll your own crypto.",
            "crypto-003": "Use cryptographically secure random number generators (CSPRNG): SecureRandom in Java, secrets in Python, crypto in Node.js."
        }
        return guidance.get(self.rule.rule_id, "Review and remediate based on security best practices for this vulnerability class.")

    def _generate_safe_fix(self) -> str:
        """Generate safe code example."""
        fixes = {
            "sqli-001": '''// Java - Safe
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();

// Python - Safe
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

// JavaScript - Safe
const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);''',
            "xss-001": '''// JavaScript - Safe (React)
// Auto-escaping by default
<div>{userInput}</div>

// JavaScript - Safe (manual escaping)
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Java - Safe (JSP)
<c:out value="${userInput}" />''',
            "cmdi-001": '''// Java - Safe
// Use ProcessBuilder with array, no shell interpretation
new ProcessBuilder("ls", directory).start();

// Python - Safe
# Avoid shell=True, use list of arguments
subprocess.run(["ls", directory], capture_output=True)

// If you must parse user input, validate strictly:
ALLOWED_COMMANDS = {"ls", "cat", "grep"}
if command not in ALLOWED_COMMANDS:
    raise ValueError("Command not allowed")''',
            "pathtraversal-001": '''// Java - Safe
Path basePath = Paths.get("/app/uploads").normalize();
Path userPath = basePath.resolve(userInput).normalize();
if (!userPath.startsWith(basePath)) {
    throw new SecurityException("Path traversal detected");
}

// Python - Safe
from pathlib import Path
base_path = Path("/app/uploads").resolve()
user_path = (base_path / user_input).resolve()
if not str(user_path).startswith(str(base_path)):
    raise ValueError("Path traversal detected")''',
            "deserialization-001": '''// Java - Safe
// Use JSON instead of Java serialization
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(jsonString, User.class);

// Python - Safe
# Use JSON instead of pickle
import json
data = json.loads(user_input)

# Or use safe YAML loading
import yaml
data = yaml.safe_load(user_input)  # NOT yaml.load()''',
            "ssrf-001": '''// Java - Safe
URL url = new URL(userInput);
if (!ALLOWED_HOSTS.contains(url.getHost())) {
    throw new SecurityException("Host not allowed");
}
// Also validate protocol, port, path

// Python - Safe
from urllib.parse import urlparse
parsed = urlparse(user_url)
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError("Host not allowed")
if parsed.scheme != "https":
    raise ValueError("Only HTTPS allowed")''',
            "crypto-001": '''// Java - Safe
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
String hash = encoder.encode(password);
boolean matches = encoder.matches(password, hash);

// Python - Safe
import bcrypt
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
if bcrypt.checkpw(password.encode(), hash):
    # Valid password''',
            "crypto-003": '''// Java - Safe
SecureRandom random = new SecureRandom();
byte[] token = new byte[32];
random.nextBytes(token);
String tokenStr = Base64.getEncoder().encodeToString(token);

// Python - Safe
import secrets
token = secrets.token_urlsafe(32)'''
        }
        return fixes.get(self.rule.rule_id, "// Refer to secure coding guidelines for this vulnerability class")

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "rule_id": self.rule.rule_id,
            "cwe": self.rule.cwe,
            "severity": self.rule.severity,
            "confidence": self.confidence,
            "file": self.file,
            "line_range": {"start": self.line_start, "end": self.line_end},
            "sink_source_summary": self.sink_source_summary,
            "evidence_snippet": self.evidence_snippet,
            "reasoning": self.reasoning,
            "fix_guidance": self.fix_guidance,
            "safe_fix_example": self.safe_fix_example
        }
        # Include AI analysis if available
        if self.ai_analysis:
            result["ai_analysis"] = self.ai_analysis
        if self.ai_suggested_fix:
            result["ai_suggested_fix"] = self.ai_suggested_fix
        if self.ai_is_false_positive is not None:
            result["ai_is_false_positive"] = self.ai_is_false_positive
        return result


class RuleEngine:
    """Manages vulnerability detection rules."""

    def __init__(self, ruleset: str, language: str):
        self.ruleset = ruleset
        self.language = language
        self.rules = self._load_rules()

    def _load_rules(self) -> list[VulnerabilityRule]:
        """Load rules based on ruleset and language."""
        all_rules = []
        patterns = get_patterns_for_language(self.language)
        active_cwes = get_active_cwes(self.ruleset)

        for rule_id, cwe, name, severity in RULE_DEFINITIONS:
            if cwe in active_cwes and rule_id in patterns:
                all_rules.append(VulnerabilityRule(rule_id, cwe, name, severity, {rule_id: patterns[rule_id]}))

        return all_rules


class SecurityAuditor:
    """Main auditor class that coordinates scanning."""

    def __init__(self, target_path: str, language: str, ruleset: str, output_dir: str,
                 use_ai: bool = False, auto_ai: bool = False, report_lang: str = "zh",
                 skill_mode: bool = False,
                 api_key: str | None = None, confidence_threshold: str = "low",
                 changed_files: Optional[list[str]] = None, git_diff_range: str | None = None,
                 exclude_patterns: Optional[list[str]] = None, ignore_file: str | None = None,
                 config_path: str | None = None):
        self.target_path = Path(target_path)
        self.language = language
        self.ruleset = ruleset
        self.output_dir = Path(output_dir)
        self.use_ai = use_ai
        self.auto_ai = auto_ai
        self.skill_mode = skill_mode
        self.report_lang = report_lang
        self.api_key = api_key
        self.confidence_threshold = confidence_threshold
        self.changed_files = changed_files or []
        self.git_diff_range = git_diff_range
        self.config_path = config_path
        self.exclude_patterns = exclude_patterns or []
        self.ignore_file = ignore_file
        self.ignore_patterns = list(self.exclude_patterns)
        if ignore_file:
            self.ignore_patterns = combine_patterns(self.ignore_patterns, load_ignore_patterns(ignore_file))
        self.is_enterprise = api_key is not None
        self.engine = RuleEngine(ruleset, language)
        self.context_analyzer = ContextAnalyzer(language)
        self.findings: list[Finding] = []
        self.files_analyzed = 0
        self.lines_analyzed = 0
        self.ai_analyzer = None

        if use_ai:
            try:
                from .ai_analyzer import AIAnalyzer
                self.ai_analyzer = AIAnalyzer()
                print("AI analysis enabled")
            except ImportError:
                print("Warning: AI analyzer not available. Install dependencies to use --use-ai")
                self.use_ai = False

    def _get_files(self) -> list[Path]:
        """Get list of source files to analyze."""
        exts = get_extensions_for_language(self.language)

        files = []
        if self.target_path.is_file():
            files = [self.target_path]
        else:
            for ext in exts:
                files.extend(self.target_path.rglob(f"*{ext}"))

        filtered = self._filter_files_by_scope(files)
        return self._filter_ignored_files(filtered)

    def _scan_basis(self) -> str:
        """Return a user-facing description of the scan basis."""
        if self.report_lang == "zh":
            basis_by_ruleset = {
                "all": "基于 CWE Top 25 与 OWASP Top 10 对齐的本地规则集",
                "top25": "基于 CWE Top 25 对齐的本地规则集",
                "owasp": "基于 OWASP Top 10 对齐的本地规则集",
                "top10": "基于 OWASP Top 10 对齐的本地规则集",
            }
        else:
            basis_by_ruleset = {
                "all": "Local rule set aligned to CWE Top 25 and OWASP Top 10",
                "top25": "Local rule set aligned to CWE Top 25",
                "owasp": "Local rule set aligned to OWASP Top 10",
                "top10": "Local rule set aligned to OWASP Top 10",
            }
        return basis_by_ruleset.get(self.ruleset, basis_by_ruleset["all"])

    def _get_scan_root(self) -> Path:
        """Return the directory root used for local file resolution."""
        return self.target_path if self.target_path.is_dir() else self.target_path.parent

    def _get_git_root(self) -> Optional[Path]:
        """Return the git repository root for the target path, if any."""
        scan_root = self._get_scan_root()
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(scan_root),
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode != 0:
            return None
        return Path(result.stdout.strip())

    def _collect_changed_file_inputs(self) -> list[str]:
        """Collect changed-file candidates from explicit inputs and git diff."""
        collected = list(self.changed_files)

        if self.git_diff_range:
            scan_root = self._get_scan_root()
            result = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=ACMR", self.git_diff_range, "--"],
                cwd=str(scan_root),
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode != 0:
                print(
                    f"Warning: Unable to resolve git diff range {self.git_diff_range}: {result.stderr.strip()}",
                    file=sys.stderr
                )
            else:
                collected.extend(line.strip() for line in result.stdout.splitlines() if line.strip())

        normalized = []
        for item in collected:
            for part in re.split(r"[\n,]", item):
                part = part.strip()
                if part:
                    normalized.append(part)

        deduped = []
        seen = set()
        for item in normalized:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped

    def _resolve_changed_file(self, raw_path: str) -> Path:
        """Resolve an input path from git diff or CI against likely roots."""
        path = Path(raw_path)
        if path.is_absolute():
            return path.resolve()

        scan_root = self._get_scan_root()
        candidates = []
        git_root = self._get_git_root()
        if git_root is not None:
            candidates.append(git_root / path)
        candidates.append(scan_root / path)
        candidates.append(Path.cwd() / path)

        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved.exists():
                return resolved

        return candidates[0].resolve()

    def _filter_files_by_scope(self, files: list[Path]) -> list[Path]:
        """Restrict scanning to changed files when PR/MR scope is requested."""
        changed_inputs = self._collect_changed_file_inputs()
        if not changed_inputs:
            return files

        allowed_files = {self._resolve_changed_file(path) for path in changed_inputs}
        return [file_path for file_path in files if file_path.resolve() in allowed_files]

    def _filter_ignored_files(self, files: list[Path]) -> list[Path]:
        """Apply exclude and ignore-file patterns to the candidate file list."""
        if not self.ignore_patterns:
            return files

        scan_root = self._get_scan_root()
        filtered = []
        for file_path in files:
            candidate_paths = [str(file_path)]
            try:
                candidate_paths.append(str(file_path.relative_to(scan_root)))
            except ValueError:
                pass
            try:
                candidate_paths.append(str(file_path.relative_to(Path.cwd())))
            except ValueError:
                pass

            if any(should_ignore_path(candidate, self.ignore_patterns) for candidate in candidate_paths):
                continue
            filtered.append(file_path)
        return filtered

    def _analyze_file(self, file_path: Path) -> list[Finding]:
        """Analyze a single file for vulnerabilities."""
        findings = []
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            self.lines_analyzed += len(lines)
            relative_file = str(file_path.relative_to(self._get_scan_root()))

            for rule in self.engine.rules:
                pattern = list(rule.patterns.values())[0]
                try:
                    for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                        # Calculate line numbers
                        start_pos = match.start()
                        line_start = content[:start_pos].count('\n') + 1
                        line_end = line_start + content[start_pos:match.end()].count('\n')

                        # Get context (3 lines before and after)
                        context_start = max(0, line_start - 4)
                        context_end = min(len(lines), line_end + 3)
                        evidence = '\n'.join(lines[context_start:context_end])

                        if is_finding_suppressed(lines, line_start, rule.rule_id):
                            continue

                        context_result = self.context_analyzer.analyze(content, match, rule.rule_id)

                        # Calculate confidence based on context
                        confidence = self._calculate_confidence(content, match, rule, context_result)
                        if not self._meets_confidence_threshold(confidence):
                            continue

                        summary = context_result.get("summary")
                        sink_source_summary = summary if isinstance(summary, str) else None

                        finding = Finding(
                            rule=rule,
                            file=relative_file,
                            line_range=(line_start, max(line_start, line_end)),
                            evidence=evidence,
                            confidence=confidence,
                            sink_source_summary=sink_source_summary,
                        )
                        if context_result.get("sanitization_detected"):
                            finding.reasoning += " Potential sanitization detected nearby; manual review recommended."
                        findings.append(finding)
                except re.error as e:
                    print(f"Regex error in rule {rule.rule_id}: {e}", file=sys.stderr)

        except Exception as e:
            print(f"Error analyzing {file_path}: {e}", file=sys.stderr)

        return findings

    def _calculate_confidence(
        self,
        content: str,
        match: re.Match,
        rule: VulnerabilityRule,
        context_result: Optional[dict[str, Any]] = None,
    ) -> str:
        """Calculate confidence level based on context."""
        match_text = match.group(0).lower()
        if context_result and context_result.get("confidence") == "high":
            return "high"
        if context_result and context_result.get("confidence") == "low":
            return "low"

        # High confidence: clear vulnerability pattern
        high_conf_indicators = [
            "request.getparameter",
            "req.body",
            "req.query",
            "request.args",
            "@requestparam",
            "user_input",
            "userinput"
        ]

        # Low confidence: might be false positive
        low_conf_indicators = [
            "// safe",
            "sanitized",
            "escape",
            "validate",
            "whitelist",
            "test",
            "mock",
            "example"
        ]

        if any(ind in match_text or ind in content[max(0, match.start()-100):match.start()].lower() for ind in high_conf_indicators):
            return "high"
        elif any(ind in match_text or ind in content[max(0, match.start()-100):match.start()].lower() for ind in low_conf_indicators):
            return "low"
        else:
            return "medium"

    def _meets_confidence_threshold(self, confidence: str) -> bool:
        """Check whether a finding passes the configured confidence threshold."""
        confidence_order = {"low": 0, "medium": 1, "high": 2}
        return confidence_order.get(confidence, 0) >= confidence_order.get(self.confidence_threshold, 0)

    @staticmethod
    def _finding_key(rule_id: str, file_path: str, line_start: int, line_end: int) -> str:
        """Build a stable identifier for correlating a finding across phases."""
        return f"{rule_id}|{file_path}|{line_start}|{line_end}"

    def _finding_key_from_finding(self, finding: Finding) -> str:
        return self._finding_key(
            finding.rule.rule_id,
            finding.file,
            finding.line_start,
            finding.line_end
        )

    @classmethod
    def _finding_key_from_dict(cls, finding: Dict[str, Any]) -> str:
        line_range = finding.get("line_range", {})
        return cls._finding_key(
            finding.get("rule_id", ""),
            finding.get("file", ""),
            line_range.get("start", 0),
            line_range.get("end", 0)
        )

    def _call_enterprise_service(self) -> dict[str, Any] | None:
        """Call enterprise scanning service via API."""
        import urllib.error
        import urllib.request

        # Read all files and prepare for upload
        files_data = []
        for file_path in self._get_files():
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                files_data.append({
                    "path": str(file_path.relative_to(self.target_path)),
                    "content": content
                })
                self.files_analyzed += 1
                self.lines_analyzed += len(content.split('\n'))
            except Exception as e:
                print(f"Warning: Could not read {file_path}: {e}")

        # Prepare API request
        api_url = os.environ.get("ENTERPRISE_API_URL", "https://api.securityaudit.com/v1/scan")
        payload = {
            "language": self.language,
            "ruleset": self.ruleset,
            "files": files_data,
            "options": {
                "sca_enabled": True,
                "full_cwe_coverage": True,
                "report_lang": self.report_lang
            }
        }

        assert self.api_key is not None
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
            "User-Agent": f"SecurityAudit-CLI/{__version__}"
        }

        print("\nConnecting to enterprise scanning service...")
        print(f"API Endpoint: {api_url}")

        try:
            req = urllib.request.Request(
                api_url,
                data=json.dumps(payload).encode('utf-8'),
                headers=headers,
                method='POST'
            )

            with urllib.request.urlopen(req, timeout=300) as response:
                result = json.loads(response.read().decode('utf-8'))
                print("✓ Enterprise scan completed successfully")
                if not isinstance(result, dict):
                    raise TypeError("Enterprise API returned a non-object payload")
                return cast(dict[str, Any], result)

        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            print(f"\n✗ Enterprise API Error: {e.code}")
            if e.code == 401:
                print("  Invalid API key. Please check your --api-key.")
            elif e.code == 403:
                print("  API key expired or quota exceeded.")
            elif e.code == 429:
                print("  Rate limit exceeded. Please try again later.")
            else:
                print(f"  {error_body}")
            raise Exception(f"Enterprise API call failed: {e}") from e

        except urllib.error.URLError as e:
            print(f"\n✗ Connection Error: {e.reason}")
            print("  Unable to reach enterprise service. Falling back to local scan...")
            # Fall back to local scan
            self.is_enterprise = False
            return None

        except Exception as e:
            print(f"\n✗ Error calling enterprise service: {e}")
            print("  Falling back to local scan...")
            self.is_enterprise = False
            return None

    def run(self) -> dict[str, Any]:
        """Run the security audit."""
        lang_display = "中文" if self.report_lang == "zh" else "English"

        # Check if enterprise mode is enabled
        if self.is_enterprise:
            print("=" * 60)
            print("ENTERPRISE MODE")
            print("=" * 60)
            print(f"Target: {self.target_path}")
            print(f"Language: {self.language}")
            print(f"Ruleset: {self.ruleset} (Full)")
            print(f"Report language: {lang_display}")
            print("\nFeatures enabled:")
            print("  ✓ Software Composition Analysis (SCA)")
            print("  ✓ Complete CWE Top 25 coverage")
            print("  ✓ Advanced vulnerability detection")
            print("  ✓ Priority support")

            try:
                enterprise_report = self._call_enterprise_service()
                if enterprise_report:
                    self.findings = [Finding(
                        VulnerabilityRule(
                            f.get('rule_id', 'unknown'),
                            f.get('cwe', 'N/A'),
                            f.get('name', 'Unknown'),
                            f.get('severity', 'medium'),
                            {}
                        ),
                        f.get('file', ''),
                        (f.get('line_range', {}).get('start', 0), f.get('line_range', {}).get('end', 0)),
                        f.get('evidence_snippet', ''),
                        f.get('confidence', 'medium')
                    ) for f in enterprise_report.get('findings', [])]

                    # Convert back to dict format for compatibility
                    report = {
                        "scan_info": {
                            "target_path": str(self.target_path),
                            "language": self.language,
                            "scan_date": datetime.now().isoformat(),
                            "ruleset": self.ruleset,
                            "scan_basis": self._scan_basis(),
                            "version": __version__,
                            "total_files": self.files_analyzed,
                            "total_loc": self.lines_analyzed,
                            "confidence_threshold": self.confidence_threshold,
                            "scan_scope": "changed" if (self.changed_files or self.git_diff_range) else "full",
                            "config_path": self.config_path,
                            "ignored_patterns": len(self.ignore_patterns),
                            "enterprise_scan": True,
                            "sca_results": enterprise_report.get('sca_results', [])
                        },
                        "summary": enterprise_report.get('summary', {}),
                        "findings": [f.to_dict() for f in self.findings]
                    }
                    return report
            except Exception as e:
                print(f"\nEnterprise scan failed: {e}")
                print("Continuing with local scan...\n")
                self.is_enterprise = False

        # Local scan mode (Open Source)
        print("Starting security audit...")
        print(f"Target: {self.target_path}")
        print(f"Language: {self.language}")
        print(f"Ruleset: {self.ruleset}")
        print(f"Scan basis: {self._scan_basis()}")
        print(f"Confidence threshold: {self.confidence_threshold}")
        print(f"Scan scope: {'changed files' if (self.changed_files or self.git_diff_range) else 'full repository'}")
        if self.config_path:
            print(f"Config: {self.config_path}")
        if self.ignore_patterns:
            print(f"Ignore patterns: {len(self.ignore_patterns)}")
        print(f"Report language: {lang_display}")

        # Show AI analysis status
        if self.use_ai and self.ai_analyzer:
            status = self.ai_analyzer.get_status()
            if status["enabled"]:
                print(f"AI Analysis: Enabled ({status['reason']})")
            else:
                print(f"AI Analysis: Disabled - {status['reason']}")
                print("  Using rule-based analysis instead")
        else:
            print("AI Analysis: Disabled (--use-ai not specified)")
        print()

        files = self._get_files()
        print(f"Found {len(files)} files to analyze")

        for i, file_path in enumerate(files, 1):
            if i % 10 == 0 or i == len(files):
                print(f"Analyzing file {i}/{len(files)}: {file_path.name}", end='\r')
            file_findings = self._analyze_file(file_path)
            self.findings.extend(file_findings)
            self.files_analyzed += 1

        print("\n\nAnalysis complete!")
        print(f"Files analyzed: {self.files_analyzed}")
        print(f"Total lines: {self.lines_analyzed}")
        print(f"Raw findings: {len(self.findings)}")

        # AI validation phase
        if self.use_ai and self.ai_analyzer and self.ai_analyzer.enabled:
            print("\nRunning AI validation...")
            self.findings = self._ai_validate_findings()
            print(f"AI validated findings: {len(self.findings)}")

        return self._generate_report()

    def _ai_validate_findings(self) -> list[Finding]:
        """Validate findings using AI analysis."""
        if not self.ai_analyzer:
            return self.findings

        # Convert Finding objects to dicts for AI analysis
        finding_dicts = [f.to_dict() for f in self.findings]

        def progress(current, total):
            print(f"  AI analyzing {current}/{total}...", end='\r')

        # Run batch AI analysis
        validated_dicts = self.ai_analyzer.batch_analyze(finding_dicts, progress_callback=progress)
        print()  # New line after progress

        # Update findings with AI results
        validated_findings = []
        for fd in validated_dicts:
            finding_key = self._finding_key_from_dict(fd)
            original = next(
                (finding for finding in self.findings if self._finding_key_from_finding(finding) == finding_key),
                None
            )
            if original is None:
                continue
            if 'ai_analysis' in fd:
                original.ai_analysis = fd['ai_analysis']
            if 'ai_suggested_fix' in fd:
                original.ai_suggested_fix = fd['ai_suggested_fix']
            if 'ai_is_false_positive' in fd:
                original.ai_is_false_positive = fd['ai_is_false_positive']
            validated_findings.append(original)

        return validated_findings

    def _generate_report(self) -> dict[str, Any]:
        """Generate the final report structure."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        confidence_counts = {"high": 0, "medium": 0, "low": 0}

        for finding in self.findings:
            severity_counts[finding.rule.severity] += 1
            confidence_counts[finding.confidence] += 1

        report = {
            "scan_info": {
                "target_path": str(self.target_path),
                "language": self.language,
                "scan_date": datetime.now().isoformat(),
                "ruleset": self.ruleset,
                "scan_basis": self._scan_basis(),
                "version": __version__,
                "total_files": self.files_analyzed,
                "total_loc": self.lines_analyzed,
                "confidence_threshold": self.confidence_threshold,
                "scan_scope": "changed" if (self.changed_files or self.git_diff_range) else "full",
                "skill_mode": self.skill_mode,
                "config_path": self.config_path,
                "ignored_patterns": len(self.ignore_patterns)
            },
            "summary": {
                "total_findings": len(self.findings),
                "severity_counts": severity_counts,
                "confidence_counts": confidence_counts
            },
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda x: (x.rule.severity != "critical", x.rule.severity != "high", x.file))]
        }

        return report

    def save_reports(
        self,
        report: dict[str, Any],
        ai_analysis_results: dict[str, Any] | None = None,
    ):
        """Save JSON and Markdown reports."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Save JSON report
        json_path = self.output_dir / "audit-report.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\nJSON report saved: {json_path}")

        # Generate Markdown report
        md_path = self.output_dir / "audit-report.md"
        self._generate_markdown(report, md_path)
        print(f"Markdown report saved: {md_path}")

        # Generate SARIF report for code scanning integrations
        sarif_path = self.output_dir / "audit-report.sarif"
        self._generate_sarif(report, sarif_path)
        print(f"SARIF report saved: {sarif_path}")

        # Generate AI analysis report for all AI-assisted scans, including zero-finding cases.
        if self.use_ai:
            ai_report_path = self.output_dir / "audit-report-ai.md"
            self._generate_ai_report(report, ai_analysis_results or {}, ai_report_path)
            print(f"AI analysis report saved: {ai_report_path}")

        # Generate AI analysis prompt if --auto-ai is enabled
        if self.auto_ai:
            self._generate_ai_prompt(report)

    @staticmethod
    def _severity_to_sarif_level(severity: str) -> str:
        """Map internal severities to SARIF result levels."""
        severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note"
        }
        return severity_map.get(severity, "warning")

    @staticmethod
    def _severity_to_security_score(severity: str) -> str:
        """Map severities to SARIF security-severity scores."""
        severity_map = {
            "critical": "9.5",
            "high": "8.0",
            "medium": "5.0",
            "low": "2.0"
        }
        return severity_map.get(severity, "0.0")

    def _rule_name_for_id(self, rule_id: str) -> str:
        """Resolve a human-readable rule name from loaded findings."""
        for finding in self.findings:
            if finding.rule.rule_id == rule_id:
                return finding.rule.name
        return rule_id

    def _build_sarif_rules(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build SARIF rule metadata from scan findings."""
        rules = []
        seen = set()

        for finding in findings:
            rule_id = finding["rule_id"]
            if rule_id in seen:
                continue
            seen.add(rule_id)

            cwe = finding.get("cwe", "")
            help_uri = None
            if cwe.startswith("CWE-") and cwe[4:].isdigit():
                help_uri = f"https://cwe.mitre.org/data/definitions/{cwe[4:]}.html"

            rule = {
                "id": rule_id,
                "name": self._rule_name_for_id(rule_id),
                "shortDescription": {
                    "text": finding.get("sink_source_summary", rule_id)
                },
                "fullDescription": {
                    "text": finding.get("reasoning", finding.get("sink_source_summary", rule_id))
                },
                "help": {
                    "text": finding.get("fix_guidance", "Review and remediate this issue based on secure coding best practices.")
                },
                "properties": {
                    "tags": [tag for tag in [cwe, finding.get("severity"), self.language] if tag],
                    "security-severity": self._severity_to_security_score(finding.get("severity", "medium"))
                }
            }
            if help_uri:
                rule["helpUri"] = help_uri
            rules.append(rule)

        return rules

    def _build_sarif_results(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert findings to SARIF results."""
        results = []

        for finding in findings:
            line_range = finding.get("line_range", {})
            start_line = line_range.get("start", 1)
            end_line = line_range.get("end", start_line)
            message_text = finding.get("sink_source_summary", "")
            if finding.get("reasoning"):
                message_text = f"{message_text}. {finding['reasoning']}" if message_text else finding["reasoning"]

            results.append({
                "ruleId": finding["rule_id"],
                "level": self._severity_to_sarif_level(finding.get("severity", "medium")),
                "message": {
                    "text": message_text
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": Path(finding.get("file", "")).as_posix(),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": start_line,
                            "endLine": end_line,
                            "snippet": {
                                "text": finding.get("evidence_snippet", "")
                            }
                        }
                    }
                }],
                "partialFingerprints": {
                    "primaryLocationLineHash": self._finding_key_from_dict(finding)
                },
                "properties": {
                    "confidence": finding.get("confidence", "medium"),
                    "cwe": finding.get("cwe", ""),
                    "security-severity": self._severity_to_security_score(finding.get("severity", "medium"))
                }
            })

        return results

    def _generate_sarif(self, report: Dict[str, Any], output_path: Path):
        """Generate a SARIF 2.1.0 report for code scanning platforms."""
        findings = report.get("findings", [])
        scan_root = self._get_scan_root().resolve()
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "security-code-audit",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://cwe.mitre.org/",
                        "rules": self._build_sarif_rules(findings)
                    }
                },
                "automationDetails": {
                    "id": f"{self.language}-{report['scan_info'].get('scan_scope', 'full')}-{self.ruleset}"
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": scan_root.as_uri()
                    }
                },
                "columnKind": "utf16CodeUnits",
                "invocations": [{
                    "executionSuccessful": True
                }],
                "results": self._build_sarif_results(findings)
            }]
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)

    def _generate_ai_prompt(self, report: Dict[str, Any]):
        """Generate AI analysis prompt for Claude Code integration."""
        prompt_path = self.output_dir / "ai-analysis-prompt.txt"

        findings = report['findings']
        summary = report['summary']

        # Build findings summary
        findings_text = []
        for i, f in enumerate(findings[:10], 1):  # Limit to first 10 for brevity
            findings_text.append(f"""
{i}. {f['rule_id']} ({f['cwe']}) - {f['severity'].upper()}
   File: {f['file']}:{f['line_range']['start']}
   Summary: {f['sink_source_summary']}
""")

        if len(findings) > 10:
            more_text = f"\n... 还有 {len(findings) - 10} 个发现\n" if self.report_lang == "zh" else f"\n... and {len(findings) - 10} more findings\n"
            findings_text.append(more_text)

        if self.report_lang == "zh":
            prompt = f"""# 安全审计 AI 分析请求

## 扫描摘要
- **目标**: {report['scan_info']['target_path']}
- **总发现数**: {summary['total_findings']}
- **Critical**: {summary['severity_counts']['critical']}
- **High**: {summary['severity_counts']['high']}
- **Medium**: {summary['severity_counts']['medium']}

## 主要发现
{''.join(findings_text)}

## AI 分析请求

请帮我分析以上安全扫描结果：

1. **验证误报**: 哪些发现可能是误报？请检查是否有输入验证、白名单过滤等安全措施
2. **数据流追踪**: 对于真实漏洞，追踪数据如何从用户输入流到危险函数
3. **风险评级**: 基于实际可利用性重新评估风险等级
4. **修复建议**: 为每个真实漏洞提供具体的修复代码

报告文件位置:
- JSON: {self.output_dir}/audit-report.json
- Markdown: {self.output_dir}/audit-report.md

你可以直接说 "AI深度分析" 让我开始分析。
"""
        else:
            prompt = f"""# Security Audit AI Analysis Request

## Scan Summary
- **Target**: {report['scan_info']['target_path']}
- **Total Findings**: {summary['total_findings']}
- **Critical**: {summary['severity_counts']['critical']}
- **High**: {summary['severity_counts']['high']}
- **Medium**: {summary['severity_counts']['medium']}

## Top Findings
{''.join(findings_text)}

## AI Analysis Request

Please help me analyze the security scan results:

1. **Verify False Positives**: Which findings might be false positives? Check for input validation, whitelist filtering, and other security measures.
2. **Data Flow Tracing**: For real vulnerabilities, trace how data flows from user input to dangerous functions.
3. **Risk Assessment**: Re-evaluate risk levels based on actual exploitability.
4. **Fix Recommendations**: Provide specific fix code for each real vulnerability.

Report file locations:
- JSON: {self.output_dir}/audit-report.json
- Markdown: {self.output_dir}/audit-report.md

Just say "AI Analysis" to let me start analyzing.
"""

        with open(prompt_path, 'w', encoding='utf-8') as f:
            f.write(prompt)

        print(f"\n🤖 AI analysis prompt saved: {prompt_path}")
        print("\n" + "="*60)
        print("💡 To get AI analysis, you can:")
        print("   1. Say: 'AI深度分析'")
        print("   2. Or ask: '帮我验证这些安全扫描结果'")
        print("="*60)

    def _generate_ai_report(self, report: Dict[str, Any], ai_results: Dict[str, Any], output_path: Path):
        """Generate AI deep analysis report."""
        info = report["scan_info"]
        findings = report["findings"]

        if self.report_lang == "zh":
            md = f"""# 🤖 AI 深度分析报告

## 执行摘要

| 属性 | 值 |
|----------|-------|
| **扫描目标** | {info['target_path']} |
| **扫描时间** | {info['scan_date']} |
| **总发现数** | {len(findings)} |
| **AI 验证状态** | ✅ 已完成 |

### AI 研判结论

"""
        else:
            md = f"""# 🤖 AI Deep Analysis Report

## Executive Summary

| Property | Value |
|----------|-------|
| **Target** | {info['target_path']} |
| **Scan Date** | {info['scan_date']} |
| **Total Findings** | {len(findings)} |
| **AI Validation** | ✅ Completed |

### AI Analysis Conclusion

"""

        # Add overall assessment
        if self.report_lang == "zh":
            md += """本报告由 AI 对原始扫描结果进行深度分析生成，包括：
- 漏洞真实性验证（识别误报）
- 数据流追踪分析
- 可利用性评估
- 具体修复代码建议

---

## 详细验证结果

"""
        else:
            md += """This report is generated by AI deep analysis of the original scan results, including:
- Vulnerability verification (false positive identification)
- Data flow tracing analysis
- Exploitability assessment
- Specific fix code recommendations

---

## Detailed Verification Results

"""

        if not findings:
            if self.report_lang == "zh":
                md += """当前扫描范围内未发现命中的安全漏洞规则，AI 复核结论如下：

- 已完成对扫描结果的二次确认
- 当前扫描范围内没有需要进一步修复的已确认漏洞
- 如果这与预期不符，建议检查扫描范围、语言参数、忽略规则和置信度阈值

---

"""
            else:
                md += """No security findings were matched within the scanned scope. AI review conclusion:

- Secondary review of the scan result is complete
- No confirmed vulnerabilities require remediation within the current scan scope
- If this is unexpected, review the scan scope, language selection, ignore rules, and confidence threshold

---

"""

        # Add analysis for each finding
        for i, finding in enumerate(findings, 1):
            # Get AI analysis for this finding if available
            finding_key = self._finding_key_from_dict(finding)
            ai_result = ai_results.get(finding_key, ai_results.get(finding['rule_id'], {}))
            finding_ai_analysis = finding.get('ai_analysis', {})
            if isinstance(finding_ai_analysis, dict):
                fallback_reasoning = finding_ai_analysis.get('ai_reasoning', '')
            else:
                fallback_reasoning = str(finding_ai_analysis)
            ai_reasoning = ai_result.get('reasoning', fallback_reasoning)
            is_false_positive = ai_result.get('is_false_positive', finding.get('ai_is_false_positive', False))
            fix_code = ai_result.get('fix_code', finding.get('ai_suggested_fix', ''))

            if self.report_lang == "zh":
                status_text = "✅ 确认真实漏洞" if not is_false_positive else "❌ 判定为误报"
                md += f"""### {i}. {finding['rule_id']} [{finding['severity'].upper()}] - {status_text}

**基本信息：**
- **CWE**: {finding['cwe']}
- **文件**: `{finding['file']}:{finding['line_range']['start']}`
- **原始置信度**: {finding['confidence']}

**AI 验证结果：**
{ai_reasoning if ai_reasoning else '该漏洞经过分析确认为真实存在的安全问题。'}

**修复建议代码：**
```java
{fix_code if fix_code else finding.get('safe_fix_example', '// 请参考常规报告中的修复建议')}
```

---

"""
            else:
                status_text = "✅ Confirmed Real" if not is_false_positive else "❌ False Positive"
                md += f"""### {i}. {finding['rule_id']} [{finding['severity'].upper()}] - {status_text}

**Basic Information:**
- **CWE**: {finding['cwe']}
- **File**: `{finding['file']}:{finding['line_range']['start']}`
- **Original Confidence**: {finding['confidence']}

**AI Verification:**
{ai_reasoning if ai_reasoning else 'This vulnerability is confirmed as a real security issue after analysis.'}

**Recommended Fix:**
```java
{fix_code if fix_code else finding.get('safe_fix_example', '// Please refer to fix guidance in the standard report')}
```

---

"""

        # Add summary section
        if not findings:
            if self.report_lang == "zh":
                md += """## 后续建议

- 如果这是一个安全基线扫描结果，可以继续保持当前防护措施
- 如果你预期这里应当命中漏洞，请优先检查扫描路径、语言选择和增量扫描范围
- 如需更深一层的业务逻辑审计，建议继续做人工审计或后续 AI 主审计

---

## 免责声明

本 AI 分析报告基于静态代码分析和模式识别生成，仅供参考：
- 无法保证发现所有安全漏洞
- 可能遗漏运行时相关的安全问题
- 建议结合人工代码审查和渗透测试进行全面评估

---

*本报告由 Claude Code AI 辅助生成*
"""
            else:
                md += """## Recommended Next Steps

- If this is a baseline scan, keep the current controls in place
- If you expected findings here, review the scan path, language selection, and incremental scan scope
- For deeper business-logic issues, continue with manual review or a future AI-first audit flow

---

## Disclaimer

This AI analysis report is generated based on static code analysis and pattern recognition:
- Cannot guarantee discovery of all security vulnerabilities
- May miss runtime-related security issues
- Manual review and penetration testing are still recommended

---

*This report was generated with Claude Code AI assistance*
"""
        elif self.report_lang == "zh":
            md += """## 修复优先级建议

基于 AI 分析，建议按以下优先级修复：

### 🔴 立即修复（Critical - 真实可利用）
- 所有 Critical 级别漏洞均已确认为真实可利用
- 建议 24 小时内完成修复

### 🟠 高优先级（High - 需要关注）
- High 级别漏洞需在一周内修复
- 部分可能受限于特定条件才能利用

### 🟡 中优先级（Medium）
- 建议在下一个迭代周期修复
- 注意硬编码密钥等配置类问题

---

## 免责声明

本 AI 分析报告基于静态代码分析和模式识别生成，仅供参考：
- 无法保证发现所有安全漏洞
- 可能遗漏运行时相关的安全问题
- 修复代码建议需结合具体业务场景验证
- 建议结合人工代码审查和渗透测试进行全面评估

---

*本报告由 Claude Code AI 辅助生成*
"""
        else:
            md += """## Remediation Priority

Based on AI analysis, recommended fix priorities:

### 🔴 Immediate (Critical - Confirmed Exploitable)
- All Critical vulnerabilities confirmed as real and exploitable
- Recommend fix within 24 hours

### 🟠 High Priority (High - Requires Attention)
- High severity vulnerabilities should be fixed within one week
- Some may require specific conditions to exploit

### 🟡 Medium Priority (Medium)
- Recommend fixing in next iteration
- Pay attention to configuration issues like hardcoded keys

---

## Disclaimer

This AI analysis report is generated based on static code analysis and pattern recognition:
- Cannot guarantee discovery of all security vulnerabilities
- May miss runtime-related security issues
- Fix code recommendations should be validated against specific business contexts
- Recommend combining with manual code review and penetration testing

---

*This report was generated with Claude Code AI assistance*
"""

        # Add enterprise promotion banner (only for open source version)
        if not self.is_enterprise:
            if self.report_lang == "zh":
                md += """
---

## 💼 升级到企业版

当前使用的是开源版，升级到企业版可获取更完整的安全检测能力：

| 功能 | 开源版 | 企业版 |
|------|--------|--------|
| 规则覆盖 | ⚠️ 部分 | ✅ 全部规则 |
| 软件成分分析(SCA) | ❌ | ✅ 检测第三方组件漏洞、许可证分析 |
| 自定义规则引擎 | ❌ | ✅ 支持企业私有规则 |
| 高级误报过滤 | ❌ | ✅ AI增强分析 |
| 技术支持 | 社区支持 | 优先支持 |

**使用企业版，请获取 API Key：**
```bash
python -m security_code_audit \
  --path ./src \
  --language java \
  --api-key YOUR_ENTERPRISE_API_KEY
```

咨询电话：400-6059-110
https://www.dbappsecurity.com.cn
杭州安恒信息技术股份有限公司
"""
            else:
                md += """
---

## 💼 Upgrade to Enterprise

You are currently using the Open Source edition. Upgrade to Enterprise for complete security detection capabilities:

| Feature | Open Source | Enterprise |
|---------|-------------|------------|
| Rule Coverage | ⚠️ Partial | ✅ Full coverage |
| Software Composition Analysis | ❌ | ✅ Third-party vulnerability & license analysis |
| Custom Rule Engine | ❌ | ✅ Enterprise private rules |
| Advanced False Positive Filter | ❌ | ✅ AI-enhanced analysis |
| Technical Support | Community | Priority support |

**To use Enterprise edition, get your API Key:**
```bash
python -m security_code_audit \
  --path ./src \
  --language java \
  --api-key YOUR_ENTERPRISE_API_KEY
```

Contact: 400-6059-110
https://www.dbappsecurity.com.cn
DBAPPSecurity Co., Ltd.
"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)

    def _generate_markdown(self, report: Dict[str, Any], output_path: Path):
        """Generate human-readable Markdown report."""
        info = report["scan_info"]
        summary = report["summary"]
        findings = report["findings"]

        # Language translations
        i18n = {
            "zh": {
                "title": "安全审计报告",
                "exec_summary": "执行摘要",
                "property": "属性",
                "value": "值",
                "target": "扫描目标",
                "scan_date": "扫描时间",
                "rule_set": "规则集",
                "scan_basis": "扫描依据",
                "total_files": "文件总数",
                "loc": "代码行数",
                "findings_summary": "发现汇总",
                "severity": "严重程度",
                "count": "数量",
                "risk_distribution": "风险分布",
                "detailed_findings": "详细发现",
                "rule_id": "规则ID",
                "confidence": "置信度",
                "file": "文件",
                "line_range": "行范围",
                "sink_source": "污点流向摘要",
                "evidence": "证据",
                "reasoning": "原理说明",
                "fix_guidance": "修复建议",
                "safe_fix": "安全修复示例",
                "ai_analysis": "AI 分析",
                "ai_confidence": "AI 置信度",
                "data_flow": "数据流追踪",
                "sanitization": "检测到净化措施",
                "yes": "是",
                "no": "否",
                "remediation_priority": "修复优先级",
                "immediate": "立即修复 (Critical)",
                "high_priority": "高优先级",
                "medium_priority": "中优先级",
                "methodology": "方法论",
                "limitations": "局限性",
            },
            "en": {
                "title": "Security Audit Report",
                "exec_summary": "Executive Summary",
                "property": "Property",
                "value": "Value",
                "target": "Target",
                "scan_date": "Scan Date",
                "rule_set": "Rule Set",
                "scan_basis": "Scan Basis",
                "total_files": "Total Files",
                "loc": "Lines of Code",
                "findings_summary": "Findings Summary",
                "severity": "Severity",
                "count": "Count",
                "risk_distribution": "Risk Distribution",
                "detailed_findings": "Detailed Findings",
                "rule_id": "Rule ID",
                "confidence": "Confidence",
                "file": "File",
                "line_range": "Line Range",
                "sink_source": "Sink → Source Summary",
                "evidence": "Evidence",
                "reasoning": "Reasoning",
                "fix_guidance": "Fix Guidance",
                "safe_fix": "Safe Fix Example",
                "ai_analysis": "AI Analysis",
                "ai_confidence": "AI Confidence",
                "data_flow": "Data Flow Tracing",
                "sanitization": "Sanitization Detected",
                "yes": "Yes",
                "no": "No",
                "remediation_priority": "Remediation Priority",
                "immediate": "Immediate (Critical)",
                "high_priority": "High Priority",
                "medium_priority": "Medium Priority",
                "methodology": "Methodology",
                "limitations": "Limitations",
            }
        }

        t = i18n.get(self.report_lang, i18n["zh"])

        def severity_bar(count: int, total: int, char: str = "█") -> str:
            if total == 0:
                return ""
            length = min(50, max(1, int(count / max(total, 1) * 30)))
            return char * length

        # Build the markdown content
        md = f"""# {t['title']}

## {t['exec_summary']}

| {t['property']} | {t['value']} |
|----------|-------|
| **{t['target']}** | {info['target_path']} |
| **Language** | {info['language']} |
| **{t['scan_date']}** | {info['scan_date']} |
| **{t['rule_set']}** | {info['ruleset']} |
| **{t['scan_basis']}** | {info.get('scan_basis', 'N/A')} |
| **Confidence Threshold** | {info.get('confidence_threshold', 'low')} |
| **Scan Scope** | {info.get('scan_scope', 'full')} |
| **Config Path** | {info.get('config_path', 'N/A') or 'N/A'} |
| **Ignored Patterns** | {info.get('ignored_patterns', 0)} |
| **{t['total_files']}** | {info['total_files']} |
| **{t['loc']}** | {info['total_loc']} |

### {t['findings_summary']}

| {t['severity']} | {t['count']} |
|----------|-------|
| 🔴 Critical | {summary['severity_counts']['critical']} |
| 🟠 High | {summary['severity_counts']['high']} |
| 🟡 Medium | {summary['severity_counts']['medium']} |
| 🟢 Low | {summary['severity_counts']['low']} |
| **Total** | **{summary['total_findings']}** |

## {t['risk_distribution']}

```
Critical: {severity_bar(summary['severity_counts']['critical'], summary['total_findings'])} {summary['severity_counts']['critical']}
High:     {severity_bar(summary['severity_counts']['high'], summary['total_findings'])} {summary['severity_counts']['high']}
Medium:   {severity_bar(summary['severity_counts']['medium'], summary['total_findings'])} {summary['severity_counts']['medium']}
Low:      {severity_bar(summary['severity_counts']['low'], summary['total_findings'])} {summary['severity_counts']['low']}
```

## {t['detailed_findings']}

"""

        for i, finding in enumerate(findings, 1):
            md += f"""### {i}. {finding['rule_id']} [{finding['severity'].upper()}]

**{t['rule_id']}**: `{finding['rule_id']}`
**CWE**: {finding['cwe']}
**{t['confidence']}**: {finding['confidence']}
**{t['file']}**: `{finding['file']}`
**{t['line_range']}**: {finding['line_range']['start']} - {finding['line_range']['end']}

#### {t['sink_source']}

{finding['sink_source_summary']}

#### {t['evidence']}

```{self.language}
{finding['evidence_snippet']}
```

#### {t['reasoning']}

{finding['reasoning']}

#### {t['fix_guidance']}

{finding['fix_guidance']}

#### {t['safe_fix']}

```{self.language}
{finding['safe_fix_example']}
```
"""

            # Add AI Analysis section if available
            if 'ai_analysis' in finding:
                ai = finding['ai_analysis']
                yes_text = f"{t['yes']} ⚠️" if self.report_lang == "zh" else f"{t['yes']} ⚠️"
                no_text = t['no']
                md += f"""
#### 🤖 {t['ai_analysis']}

**{t['ai_confidence']}**: {ai.get('ai_confidence', 'N/A')}

**{t['data_flow']}**: {ai.get('data_flow', 'N/A')}

**{t['sanitization']}**: {yes_text if ai.get('sanitization_detected') else no_text}

{ai.get('ai_reasoning', '')}
"""
                if 'ai_suggested_fix' in finding:
                    md += f"""
**AI Suggested Fix**:
```java
{finding['ai_suggested_fix']}
```
"""

            md += """
---

"""

        # Add remediation priority section
        critical_findings = [f for f in findings if f['severity'] == 'critical']
        high_findings = [f for f in findings if f['severity'] == 'high']
        medium_findings = [f for f in findings if f['severity'] == 'medium']

        md += f"""## {t['remediation_priority']}

"""

        if critical_findings:
            md += f"### {t['immediate']}\n"
            for f in critical_findings[:10]:  # Limit to 10
                md += f"- [ ] `{f['file']}:{f['line_range']['start']}` - {f['rule_id']} ({f['cwe']})\n"
            if len(critical_findings) > 10:
                more_text = f"... 还有 {len(critical_findings) - 10} 个" if self.report_lang == "zh" else f"... and {len(critical_findings) - 10} more"
                md += f"- [ ] {more_text}\n"
            md += "\n"

        if high_findings:
            md += f"### {t['high_priority']}\n"
            for f in high_findings[:10]:
                md += f"- [ ] `{f['file']}:{f['line_range']['start']}` - {f['rule_id']} ({f['cwe']})\n"
            if len(high_findings) > 10:
                more_text = f"... 还有 {len(high_findings) - 10} 个" if self.report_lang == "zh" else f"... and {len(high_findings) - 10} more"
                md += f"- [ ] {more_text}\n"
            md += "\n"

        if medium_findings:
            md += f"### {t['medium_priority']}\n"
            for f in medium_findings[:10]:
                md += f"- [ ] `{f['file']}:{f['line_range']['start']}` - {f['rule_id']} ({f['cwe']})\n"
            if len(medium_findings) > 10:
                more_text = f"... 还有 {len(medium_findings) - 10} 个" if self.report_lang == "zh" else f"... and {len(medium_findings) - 10} more"
                md += f"- [ ] {more_text}\n"

        # Methodology and Limitations
        if self.report_lang == "zh":
            md += f"""
## {t['methodology']}

本次审计使用静态应用安全测试 (SAST) 技术：

1. **输入源识别**：识别用户输入来源（HTTP参数、请求头、请求体）
2. **危险函数检测**：定位危险的 API 调用（SQL执行、命令执行等）
3. **污点追踪**：追踪数据从输入源到危险函数的流动
4. **模式匹配**：应用漏洞特定的检测模式
5. **验证**：根据置信度和严重程度阈值过滤发现

### {t['limitations']}

- 仅分析提供的代码，不分析运行时行为
- 可能遗漏动态生成代码中的漏洞
- 复杂的净化模式可能产生误报
- 不评估基础设施或部署配置
"""
        else:
            md += f"""
## {t['methodology']}

This audit was performed using static application security testing (SAST) techniques:

1. **Source Discovery**: Identified user input sources (HTTP parameters, headers, body)
2. **Sink Analysis**: Located dangerous API calls (SQL execution, command execution, etc.)
3. **Taint Tracking**: Traced data flow from sources to sinks
4. **Pattern Matching**: Applied vulnerability-specific detection patterns
5. **Validation**: Filtered findings by confidence and severity thresholds

### {t['limitations']}

- Only analyzes the provided code, not runtime behavior
- May miss vulnerabilities in dynamically generated code
- False positives possible for complex sanitization patterns
- Does not assess infrastructure or deployment configuration
"""

        # Add enterprise promotion banner (only for open source version)
        if not self.is_enterprise:
            if self.report_lang == "zh":
                md += """
---

## 💼 升级到企业版

当前使用的是开源版，升级到企业版可获取更完整的安全检测能力：

| 功能 | 开源版 | 企业版 |
|------|--------|--------|
| 规则覆盖 | ⚠️ 部分 | ✅ 全部规则 |
| 软件成分分析(SCA) | ❌ | ✅ 检测第三方组件漏洞、许可证分析 |
| 自定义规则引擎 | ❌ | ✅ 支持企业私有规则 |
| 高级误报过滤 | ❌ | ✅ AI增强分析 |
| 技术支持 | 社区支持 | 优先支持 |

**使用企业版，请获取 API Key：**
```bash
python -m security_code_audit \
  --path ./src \
  --language java \
  --api-key YOUR_ENTERPRISE_API_KEY
```

咨询电话：400-6059-110
https://www.dbappsecurity.com.cn
杭州安恒信息技术股份有限公司
"""
            else:
                md += """
---

## 💼 Upgrade to Enterprise

You are currently using the Open Source edition. Upgrade to Enterprise for complete security detection capabilities:

| Feature | Open Source | Enterprise |
|---------|-------------|------------|
| Rule Coverage | ⚠️ Partial | ✅ Full coverage |
| Software Composition Analysis | ❌ | ✅ Third-party vulnerability & license analysis |
| Custom Rule Engine | ❌ | ✅ Enterprise private rules |
| Advanced False Positive Filter | ❌ | ✅ AI-enhanced analysis |
| Technical Support | Community | Priority support |

**To use Enterprise edition, get your API Key:**
```bash
python -m security_code_audit \
  --path ./src \
  --language java \
  --api-key YOUR_ENTERPRISE_API_KEY
```

Contact: 400-6059-110
https://www.dbappsecurity.com.cn
DBAPPSecurity Co., Ltd.
"""

        md += "\n"

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)


def main():
    parser = argparse.ArgumentParser(
        description="Security Code Audit Tool - SAST for CWE Top 25 and OWASP Top 10",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --path /path/to/java/project --language java
  %(prog)s --config .security-audit.toml
  %(prog)s --path ./myapp --language python --ruleset owasp --output ./reports
  %(prog)s --path ./legacy-app --language php --ruleset all
  %(prog)s --path ./dotnet-service --language csharp --ruleset all
  %(prog)s --path ./jvm-service --language kotlin --ruleset all
  %(prog)s --path ./src --language javascript --ruleset top25
  %(prog)s --path ./service --language go --git-diff-range origin/main...HEAD
        """
    )

    parser.add_argument(
        "--config",
        default=None,
        help="Path to a TOML/JSON/YAML config file (auto-discovers .security-audit.* when omitted)"
    )
    parser.add_argument(
        "--path",
        default=None,
        help="Path to code directory or file to audit"
    )
    parser.add_argument(
        "--language",
        default=None,
        choices=SUPPORTED_LANGUAGES,
        help="Programming language of the target code"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output directory for reports (default: security-code-audit/reports/<project-name>/)"
    )
    parser.add_argument(
        "--ruleset",
        default=None,
        choices=["top25", "owasp", "top10", "all"],
        help="Rule set to apply (default: all)"
    )
    parser.add_argument(
        "--confidence",
        default=None,
        choices=["high", "medium", "low"],
        help="Minimum confidence threshold for reported findings (default: low)"
    )
    parser.add_argument(
        "--exclude",
        nargs="*",
        default=None,
        help="Glob patterns to exclude from scanning"
    )
    parser.add_argument(
        "--ignore-file",
        default=None,
        help="Path to a newline-delimited ignore file"
    )
    parser.add_argument(
        "--changed-files",
        nargs="*",
        default=None,
        help="Only scan the specified changed files (space or comma separated)"
    )
    parser.add_argument(
        "--changed-files-file",
        default=None,
        help="Path to a newline-delimited file list for PR/MR scanning"
    )
    parser.add_argument(
        "--git-diff-range",
        default=None,
        help="Only scan files changed in the given git diff range, e.g. origin/main...HEAD"
    )
    parser.add_argument(
        "--use-ai",
        action="store_true",
        default=None,
        help="Enable local AI-style validation to filter likely false positives and enrich findings"
    )
    parser.add_argument(
        "--auto-ai",
        action="store_true",
        default=None,
        help="Auto-generate AI analysis prompt after scan (for Claude Code integration)"
    )
    parser.add_argument(
        "--skill-mode",
        action="store_true",
        default=None,
        help="Dialogue-friendly mode: enables AI artifacts and returns exit code 0 for findings"
    )
    parser.add_argument(
        "--report-lang",
        default=None,
        choices=["zh", "en"],
        help="Report language: zh (Chinese, default) or en (English)"
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Enterprise API key. If provided, will use enterprise scanning service with enhanced capabilities (SCA, full CWE Top 25, etc.)"
    )

    args = parser.parse_args()

    config = load_config(args.config, args.path or ".")
    if "__config_path__" in config:
        args.config = config["__config_path__"]
    config_dir = Path(config["__config_dir__"]).resolve() if "__config_dir__" in config else None

    args.path = merge_cli_with_config(args.path, config, "path")
    args.language = merge_cli_with_config(args.language, config, "language")
    args.ruleset = merge_cli_with_config(args.ruleset, config, "ruleset", "all")
    args.confidence = merge_cli_with_config(args.confidence, config, "confidence", "low")
    args.report_lang = merge_cli_with_config(args.report_lang, config, "report_lang", "zh")
    args.output = merge_cli_with_config(args.output, config, "output")
    args.api_key = merge_cli_with_config(args.api_key, config, "api_key")
    args.git_diff_range = merge_cli_with_config(args.git_diff_range, config, "git_diff_range")
    args.ignore_file = merge_cli_with_config(args.ignore_file, config, "ignore_file")
    args.changed_files_file = merge_cli_with_config(args.changed_files_file, config, "changed_files_file")
    args.use_ai = merge_cli_with_config(args.use_ai, config, "use_ai", False)
    args.auto_ai = merge_cli_with_config(args.auto_ai, config, "auto_ai", False)
    args.skill_mode = merge_cli_with_config(args.skill_mode, config, "skill_mode", False)

    if args.skill_mode:
        args.use_ai = True
        args.auto_ai = True

    if config_dir is not None:
        for attr in ("path", "output", "ignore_file", "changed_files_file"):
            value = getattr(args, attr, None)
            if value and not os.path.isabs(value):
                setattr(args, attr, str((config_dir / value).resolve()))

    if not args.path:
        print("Error: --path is required unless provided in config", file=sys.stderr)
        sys.exit(1)
    if not args.language:
        print("Error: --language is required unless provided in config", file=sys.stderr)
        sys.exit(1)
    if args.language not in SUPPORTED_LANGUAGES:
        print(f"Error: Unsupported language: {args.language}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(args.path):
        print(f"Error: Path does not exist: {args.path}", file=sys.stderr)
        sys.exit(1)
    if args.changed_files_file and not os.path.exists(args.changed_files_file):
        print(f"Error: Changed files list does not exist: {args.changed_files_file}", file=sys.stderr)
        sys.exit(1)
    if args.ignore_file and not os.path.exists(args.ignore_file):
        print(f"Error: Ignore file does not exist: {args.ignore_file}", file=sys.stderr)
        sys.exit(1)

    changed_files = list(args.changed_files or config.get("changed_files", []) or [])
    if args.changed_files_file:
        with open(args.changed_files_file, 'r', encoding='utf-8', errors='ignore') as f:
            changed_files.extend(line.strip() for line in f if line.strip())
    exclude_patterns = combine_patterns(args.exclude, config.get("exclude", []))

    # Determine output directory
    if args.output is None:
        # Auto-generate output directory based on target path
        # Get project name from target path
        target_path = Path(args.path).resolve()
        if target_path.is_file():
            project_name = target_path.stem
        else:
            project_name = target_path.name

        # Use skill's reports directory as base
        package_dir = Path(__file__).resolve().parent
        reports_base = package_dir.parent / "reports"
        args.output = reports_base / project_name

        # Create directory if it doesn't exist
        args.output.mkdir(parents=True, exist_ok=True)

    auditor = SecurityAuditor(
        target_path=args.path,
        language=args.language,
        ruleset=args.ruleset,
        output_dir=args.output,
        use_ai=args.use_ai,
        auto_ai=args.auto_ai,
        report_lang=args.report_lang,
        skill_mode=args.skill_mode,
        api_key=args.api_key,
        confidence_threshold=args.confidence,
        changed_files=changed_files,
        git_diff_range=args.git_diff_range,
        exclude_patterns=exclude_patterns,
        ignore_file=args.ignore_file,
        config_path=args.config
    )

    report = auditor.run()
    auditor.save_reports(report)

    print(f"\n{'='*60}")
    print("Audit complete!")
    print(f"Findings: {report['summary']['total_findings']}")
    print(f"  Critical: {report['summary']['severity_counts']['critical']}")
    print(f"  High: {report['summary']['severity_counts']['high']}")
    print(f"  Medium: {report['summary']['severity_counts']['medium']}")
    print(f"  Low: {report['summary']['severity_counts']['low']}")
    if args.use_ai:
        if report['summary']['total_findings'] == 0:
            if args.report_lang == "zh":
                print("AI review: completed - 当前扫描范围内未确认漏洞")
            else:
                print("AI review: completed - no confirmed vulnerabilities in the scanned scope")
        else:
            if args.report_lang == "zh":
                print(f"AI review: completed - {report['summary']['total_findings']} 个发现已完成 AI 复核")
            else:
                print(f"AI review: completed - {report['summary']['total_findings']} findings reviewed")
    if args.skill_mode:
        print("Skill mode: normalized exit code to 0 for dialogue workflows")
    print(f"{'='*60}")

    # CI mode uses non-zero exit codes for high/critical findings.
    if args.skill_mode:
        sys.exit(0)
    if report['summary']['severity_counts']['critical'] > 0:
        sys.exit(2)
    elif report['summary']['severity_counts']['high'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
