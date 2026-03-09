#!/usr/bin/env python3
"""
AI Analyzer for Security Findings
Provides intelligent analysis of security findings to reduce false positives.
This module is designed to work with Claude AI in Claude Code environment.
"""

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class AIValidationResult:
    """Result of AI validation."""
    is_vulnerable: bool
    confidence: str  # high/medium/low
    reasoning: str
    sanitized: bool  # whether sanitization was detected
    data_flow: str   # description of data flow
    suggested_fix: str


class AIAnalyzer:
    """
    Analyzes security findings using rule-based heuristics.

    Designed to be used in Claude Code environment where Claude AI
    provides the intelligent analysis directly.
    """

    def __init__(self):
        """Initialize analyzer with sanitization patterns."""
        self.enabled = True
        self._init_sanitization_patterns()

    def get_status(self) -> Dict[str, Any]:
        """Expose analyzer status in the shape expected by the CLI."""
        if self.enabled:
            return {"enabled": True, "reason": "Rule-based analyzer available"}
        return {"enabled": False, "reason": "Analyzer disabled"}

    def _init_sanitization_patterns(self):
        """Initialize sanitization indicators for each vulnerability type."""
        self.sanitization_indicators = {
            "sqli-001": [
                "preparedstatement", "?.bind", "sanitize", "validate",
                "escape", "parameter", "?", "stmt.set", "bindparam",
                "createquery", "setparameter"
            ],
            "cmdi-001": [
                "processbuilder", "array", "validate", "allowlist",
                "whitelist", "sanitized", "escape", "commandarray"
            ],
            "xss-001": [
                "escape", "encode", "sanitize", "c:out", "th:text",
                "htmlentities", "innertext", "textcontent", "encodeforhtml",
                "jsoup.clean", "owasp.encoder"
            ],
            "pathtraversal-001": [
                "normalize", "canonical", "validate", "allowlist",
                "startswith", "resolve", "realpath", "getcanonicalpath",
                "path.normalize"
            ],
            "deserialization-001": [
                "integrity", "signature", "whitelist", "lookaheaddeserializer",
                "classloader", "objectfilter", "serialkiller", "contrastsecurity"
            ],
            "ssrf-001": [
                "allowlist", "whitelist", "validate", "startswith",
                "inetaddress", "urlfilter", "hostwhitelist", "parsedurl"
            ],
            "crypto-001": [
                "bcrypt", "argon2", "scrypt", "pbkdf2", "sha256", "sha-256",
                "sha512", "sha-512", "aes", "rsa"
            ],
            "crypto-003": [
                "securerandom", "secrets.", "crypto.randombytes",
                "os.urandom", "random_bytes", "getstrongrandom"
            ],
        }

        # Patterns that strongly indicate false positive
        self.false_positive_patterns = {
            "sqli-001": [
                r"PreparedStatement\s+\w+",
                r"setString\s*\(\s*\d+",
                r"setInt\s*\(\s*\d+",
                r"createQuery\s*\([^+]*\)",
            ],
            "xss-001": [
                r"escapeHtml\s*\(",
                r"encodeForHTML\s*\(",
                r"\.text\s*\(",
                r"innerText\s*=",
            ],
        }

    def analyze_finding(self, finding: Dict[str, Any]) -> AIValidationResult:
        """
        Analyze a security finding using rule-based heuristics.

        Args:
            finding: The finding dict from regex analysis

        Returns:
            AIValidationResult with analysis results
        """
        return self._rule_based_analysis(finding)

    def _rule_based_analysis(self, finding: Dict[str, Any]) -> AIValidationResult:
        """
        Rule-based analysis to detect sanitization and reduce false positives.
        """
        code_snippet = finding.get("evidence_snippet", "").lower()
        rule_id = finding.get("rule_id", "")

        indicators = self.sanitization_indicators.get(rule_id, [])
        has_sanitization = any(ind in code_snippet for ind in indicators)

        # Check for strong false positive patterns
        is_likely_false_positive = self._check_false_positive(finding)

        if is_likely_false_positive:
            return AIValidationResult(
                is_vulnerable=False,
                confidence="low",
                reasoning="Rule-based analysis suggests this is likely a false positive due to sanitization patterns detected.",
                sanitized=True,
                data_flow="Rule-based analysis: Sanitization detected - likely false positive",
                suggested_fix=finding.get("fix_guidance", "")
            )
        elif has_sanitization:
            return AIValidationResult(
                is_vulnerable=True,
                confidence="medium",
                reasoning=f"{finding.get('reasoning', '')}\n\n[Note: Potential sanitization detected - manual review recommended]",
                sanitized=True,
                data_flow="Rule-based analysis: Sanitization patterns detected in code",
                suggested_fix=finding.get("fix_guidance", "")
            )
        else:
            return AIValidationResult(
                is_vulnerable=True,
                confidence=finding.get("confidence", "medium"),
                reasoning=finding.get("reasoning", ""),
                sanitized=False,
                data_flow="Rule-based analysis: No sanitization patterns detected",
                suggested_fix=finding.get("fix_guidance", "")
            )

    def _check_false_positive(self, finding: Dict[str, Any]) -> bool:
        """
        Check if finding is likely a false positive based on strong patterns.
        """
        import re
        code_snippet = finding.get("evidence_snippet", "")
        rule_id = finding.get("rule_id", "")

        patterns = self.false_positive_patterns.get(rule_id, [])
        for pattern in patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return True
        return False

    def prepare_for_ai_review(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Prepare findings for AI review in Claude Code.

        This formats the findings in a way that's optimal for Claude AI
        to analyze and validate.

        Returns:
            Dict with formatted findings and metadata
        """
        reviewed_findings = []

        for finding in findings:
            result = self.analyze_finding(finding)

            enhanced_finding = finding.copy()
            enhanced_finding["rule_based_analysis"] = {
                "confidence": result.confidence,
                "sanitization_detected": result.sanitized,
                "data_flow": result.data_flow,
                "likely_false_positive": not result.is_vulnerable
            }

            # Add note for potential false positives
            if not result.is_vulnerable:
                enhanced_finding["review_note"] = "Rule-based analysis suggests this may be a false positive. Recommend manual review."

            reviewed_findings.append(enhanced_finding)

        return {
            "findings": reviewed_findings,
            "summary": {
                "total": len(findings),
                "potential_false_positives": sum(
                    1 for f in reviewed_findings
                    if f.get("rule_based_analysis", {}).get("likely_false_positive")
                ),
                "with_sanitization": sum(
                    1 for f in reviewed_findings
                    if f.get("rule_based_analysis", {}).get("sanitization_detected")
                )
            }
        }

    def batch_analyze(self, findings: List[Dict[str, Any]], progress_callback=None) -> List[Dict[str, Any]]:
        """
        Analyze multiple findings in batch.

        Args:
            findings: List of findings to analyze
            progress_callback: Optional callback(current, total) for progress updates

        Returns:
            List of refined findings
        """
        refined_findings = []

        for i, finding in enumerate(findings):
            if progress_callback:
                progress_callback(i + 1, len(findings))

            result = self.analyze_finding(finding)

            # Skip likely false positives
            if not result.is_vulnerable:
                print(f"  Filtered likely false positive: {finding.get('rule_id')} at line {finding.get('line_range', {}).get('start')}")
                continue

            enhanced_finding = finding.copy()
            enhanced_finding["ai_analysis"] = {
                "ai_confidence": result.confidence,
                "sanitization_detected": result.sanitized,
                "data_flow": result.data_flow,
                "ai_reasoning": result.reasoning,
            }
            enhanced_finding["ai_suggested_fix"] = result.suggested_fix
            enhanced_finding["ai_is_false_positive"] = not result.is_vulnerable
            enhanced_finding["validation"] = {
                "method": "rule-based",
                "confidence": result.confidence,
                "sanitization_detected": result.sanitized,
                "data_flow": result.data_flow
            }

            refined_findings.append(enhanced_finding)

        return refined_findings


def generate_ai_prompt(findings: List[Dict[str, Any]], source_code: str = "") -> str:
    """
    Generate a prompt for Claude AI to validate findings.

    This function creates a structured prompt that can be used
    in Claude Code to get AI validation of findings.

    Args:
        findings: List of findings to validate
        source_code: Optional source code for context

    Returns:
        Formatted prompt string
    """
    prompt_parts = [
        "# Security Audit Validation Request",
        "",
        "Please validate the following security findings. For each finding:",
        "1. Confirm if it's a true vulnerability or false positive",
        "2. Check if sanitization is properly implemented",
        "3. Trace the data flow from source to sink",
        "4. Provide specific fix recommendations",
        "",
        "## Findings to Validate",
        ""
    ]

    for i, finding in enumerate(findings, 1):
        prompt_parts.extend([
            f"### {i}. {finding.get('rule_id')} ({finding.get('cwe')})",
            f"- **File**: {finding.get('file')}",
            f"- **Line**: {finding.get('line_range', {}).get('start')}",
            f"- **Severity**: {finding.get('severity')}",
            "",
            "**Code Evidence**:",
            "```java",
            finding.get('evidence_snippet', ''),
            "```",
            "",
            "**Initial Analysis**:",
            f"- Confidence: {finding.get('confidence', 'medium')}",
            f"- Reasoning: {finding.get('reasoning', '')[:200]}...",
            "",
            "---",
            ""
        ])

    if source_code:
        prompt_parts.extend([
            "## Full Source Code Context",
            "",
            "```java",
            source_code[:3000] if len(source_code) > 3000 else source_code,
            "```" if len(source_code) <= 3000 else "... (truncated)",
            ""
        ])

    prompt_parts.extend([
        "## Response Format",
        "",
        "For each finding, provide:",
        "- **Verdict**: True Positive / False Positive / Needs Review",
        "- **Confidence**: high/medium/low",
        "- **Analysis**: Brief explanation of your reasoning",
        "- **Sanitization Check**: Are there any sanitization measures?",
        "- **Suggested Fix**: Specific code fix if applicable",
        "",
        "Then provide an overall summary of the audit results."
    ])

    return "\n".join(prompt_parts)


if __name__ == "__main__":
    # Demo usage
    test_findings = [
        {
            "rule_id": "sqli-001",
            "cwe": "CWE-89",
            "severity": "critical",
            "evidence_snippet": 'String query = "SELECT * FROM users WHERE id = " + id;',
            "file": "Test.java",
            "line_range": {"start": 10, "end": 10},
            "confidence": "medium",
            "reasoning": "SQL injection detected"
        },
        {
            "rule_id": "sqli-001",
            "cwe": "CWE-89",
            "severity": "critical",
            "evidence_snippet": 'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");',
            "file": "Test.java",
            "line_range": {"start": 20, "end": 20},
            "confidence": "medium",
            "reasoning": "SQL injection detected"
        }
    ]

    analyzer = AIAnalyzer()

    print("=" * 60)
    print("AI Analyzer Demo (Rule-Based Mode)")
    print("=" * 60)

    for finding in test_findings:
        result = analyzer.analyze_finding(finding)
        line_range = finding.get("line_range", {})
        start_line = line_range.get("start", "?") if isinstance(line_range, dict) else "?"
        print(f"\n{finding.get('rule_id')} at line {start_line}:")
        print(f"  Is Vulnerable: {result.is_vulnerable}")
        print(f"  Confidence: {result.confidence}")
        print(f"  Sanitization: {result.sanitized}")
        print(f"  Data Flow: {result.data_flow}")

    print("\n" + "=" * 60)
    print("\nAI Review Prompt (for Claude Code):")
    print("=" * 60)
    print(generate_ai_prompt(test_findings))
