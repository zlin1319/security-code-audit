#!/usr/bin/env python3
"""
Lightweight context and taint heuristics for scan findings.
"""

import re
from typing import Dict, List


class ContextAnalyzer:
    """Applies lightweight data-flow heuristics around regex findings."""

    def __init__(self, language: str):
        self.language = language
        self.sources = self._build_sources()
        self.sanitizers = self._build_sanitizers()

    def _build_sources(self) -> List[re.Pattern]:
        source_patterns = {
            "java": [
                r"String\s+(\w+)\s*=\s*request\.getParameter",
                r"@RequestParam[^\n]*\b(\w+)\b",
            ],
            "javascript": [
                r"(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:body|query|params)",
            ],
            "typescript": [
                r"(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:body|query|params)",
            ],
            "python": [
                r"(\w+)\s*=\s*request\.(?:args|form|json)",
            ],
            "php": [
                r"\$(\w+)\s*=\s*\$_(?:GET|POST|REQUEST)",
            ],
            "csharp": [
                r"(?:string|var)\s+(\w+)\s*=\s*Request\.(?:Query|Form|Headers)",
            ],
            "kotlin": [
                r"val\s+(\w+)\s*=\s*request\.getParameter",
            ],
            "go": [
                r"(\w+)\s*:=\s*r\.(?:URL\.Query\(\)\.Get|FormValue)",
            ],
        }
        return [re.compile(pattern, re.IGNORECASE) for pattern in source_patterns.get(self.language, [])]

    def _build_sanitizers(self) -> List[str]:
        sanitizers = {
            "java": ["preparestatement", "encodeforhtml", "escapehtml", "setparameter", "validate"],
            "javascript": ["escapehtml", "textcontent", "innertext", "validator.", "sanitize"],
            "typescript": ["escapehtml", "textcontent", "innertext", "validator.", "sanitize"],
            "python": ["markupsafe", "escape", "bleach.clean", "validate"],
            "php": ["htmlspecialchars", "intval", "filter_var", "mysqli_real_escape_string"],
            "csharp": ["httputility.htmlencode", "webutility.htmlencode", "parameters.add", "tryparse"],
            "kotlin": ["preparestatement", "escapehtml", "validate"],
            "go": ["template.HTMLEscapeString", "url.QueryEscape", "strconv.Atoi"],
        }
        return sanitizers.get(self.language, [])

    @staticmethod
    def _extract_var_candidates(text: str) -> List[str]:
        patterns = [
            r"\+\s*\$?(\w+)",
            r"\(\s*\$?(\w+)\s*\)",
            r",\s*\$?(\w+)\s*\)",
            r"=\s*\$?(\w+)\s*$",
        ]
        candidates = []
        for pattern in patterns:
            candidates.extend(re.findall(pattern, text))
        return [candidate for candidate in candidates if candidate and not candidate.isupper()]

    def analyze(self, content: str, match: re.Match, rule_id: str) -> Dict[str, object]:
        """Return contextual hints derived from nearby code."""
        window_start = max(0, match.start() - 1200)
        window_end = min(len(content), match.end() + 400)
        context = content[window_start:window_end]
        context_lower = context.lower()
        match_text = match.group(0)

        tainted_vars = []
        for pattern in self.sources:
            tainted_vars.extend(pattern.findall(context))

        tainted_vars = [var[-1] if isinstance(var, tuple) else var for var in tainted_vars]
        sink_vars = self._extract_var_candidates(match_text)
        sink_vars.extend(self._extract_var_candidates(context))
        sink_vars = list(dict.fromkeys(sink_vars))

        propagated = [var for var in sink_vars if var in tainted_vars]
        sanitization_detected = any(token in context_lower for token in self.sanitizers)

        confidence = "medium"
        if propagated:
            confidence = "high"
        elif sanitization_detected:
            confidence = "low"

        if propagated:
            summary = f"Tainted variable '{propagated[0]}' appears to flow into {rule_id}"
        elif sink_vars:
            summary = f"Variable '{sink_vars[0]}' reaches a {rule_id} sink"
        else:
            summary = ""

        return {
            "confidence": confidence,
            "summary": summary,
            "tainted_variables": propagated or tainted_vars,
            "sanitization_detected": sanitization_detected,
        }
