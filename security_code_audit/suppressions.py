#!/usr/bin/env python3
"""
Ignore and inline suppression helpers.
"""

from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, List, Sequence

SUPPRESSION_MARKER = "security-code-audit:"


def load_ignore_patterns(ignore_file: str) -> List[str]:
    """Load ignore patterns from a file."""
    path = Path(ignore_file)
    patterns = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    return patterns


def should_ignore_path(relative_path: str, patterns: Sequence[str]) -> bool:
    """Check whether a relative path matches ignore patterns."""
    normalized = Path(relative_path).as_posix()
    for pattern in patterns:
        if fnmatch(normalized, pattern) or fnmatch(Path(normalized).name, pattern):
            return True
    return False


def is_finding_suppressed(
    lines: Sequence[str],
    line_start: int,
    rule_id: str,
) -> bool:
    """Support inline suppression comments near the finding."""
    start_index = max(0, line_start - 2)
    end_index = min(len(lines), line_start + 1)
    for line in lines[start_index:end_index]:
        lowered = line.lower()
        if SUPPRESSION_MARKER not in lowered:
            continue
        if "ignore-all" in lowered:
            return True
        if "disable-next-line" in lowered and rule_id.lower() in lowered:
            return True
        if "ignore" in lowered and (rule_id.lower() in lowered or "ignore" == lowered.split(SUPPRESSION_MARKER, 1)[1].strip()):
            return True
        if f"ignore {rule_id.lower()}" in lowered:
            return True
    return False


def combine_patterns(*pattern_sets: Iterable[str]) -> List[str]:
    """Merge ignore/exclude patterns with stable order and deduplication."""
    merged = []
    seen = set()
    for pattern_set in pattern_sets:
        for pattern in pattern_set or []:
            if pattern in seen:
                continue
            seen.add(pattern)
            merged.append(pattern)
    return merged
