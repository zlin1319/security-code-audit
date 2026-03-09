# Security Audit Report

## Executive Summary

| Property | Value |
|----------|-------|
| **Target** | {{target_path}} |
| **Language** | {{language}} |
| **Scan Date** | {{scan_date}} |
| **Rule Set** | {{ruleset}} |
| **Total Files** | {{total_files}} |
| **Lines of Code** | {{total_loc}} |

### Findings Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {{critical_count}} |
| 🟠 High | {{high_count}} |
| 🟡 Medium | {{medium_count}} |
| 🟢 Low | {{low_count}} |
| **Total** | **{{total_findings}}** |

## Risk Distribution

```
Critical: {{critical_bar}} {{critical_count}}
High:     {{high_bar}} {{high_count}}
Medium:   {{medium_bar}} {{medium_count}}
Low:      {{low_bar}} {{low_count}}
```

## Detailed Findings

{{#findings}}

### {{index}}. {{title}} [{{severity}}]

**Rule ID**: `{{rule_id}}`
**CWE**: {{cwe}}
**Confidence**: {{confidence}}
**File**: `{{file}}`
**Line Range**: {{line_start}} - {{line_end}}

#### Sink → Source Summary

{{sink_source_summary}}

#### Evidence

```{{language}}
{{{evidence_snippet}}}
```

#### Reasoning

{{reasoning}}

#### Fix Guidance

{{fix_guidance}}

#### Safe Fix Example

```{{language}}
{{{safe_fix_example}}}
```

---

{{/findings}}

## OWASP Top 10 Coverage

| Category | Findings | Status |
|----------|----------|--------|
| A01 - Broken Access Control | {{a01_count}} | {{a01_status}} |
| A02 - Cryptographic Failures | {{a02_count}} | {{a02_status}} |
| A03 - Injection | {{a03_count}} | {{a03_status}} |
| A04 - Insecure Design | {{a04_count}} | {{a04_status}} |
| A05 - Security Misconfiguration | {{a05_count}} | {{a05_status}} |
| A06 - Vulnerable Components | {{a06_count}} | {{a06_status}} |
| A07 - Auth Failures | {{a07_count}} | {{a07_status}} |
| A08 - Data Integrity | {{a08_count}} | {{a08_status}} |
| A09 - Logging Failures | {{a09_count}} | {{a09_status}} |
| A10 - SSRF | {{a10_count}} | {{a10_status}} |

## CWE Top 25 Coverage

{{#cwe_coverage}}
- {{cwe_id}} ({{cwe_name}}): {{finding_count}} finding(s)
{{/cwe_coverage}}

## Remediation Priority

### Immediate (Critical)
{{#critical_findings}}
- [ ] `{{file}}:{{line_start}}` - {{title}} ({{cwe}})
{{/critical_findings}}

### High Priority
{{#high_findings}}
- [ ] `{{file}}:{{line_start}}` - {{title}} ({{cwe}})
{{/high_findings}}

### Medium Priority
{{#medium_findings}}
- [ ] `{{file}}:{{line_start}}` - {{title}} ({{cwe}})
{{/medium_findings}}

## Methodology

This audit was performed using static application security testing (SAST) techniques:

1. **Source Discovery**: Identified user input sources (HTTP parameters, headers, body)
2. **Sink Analysis**: Located dangerous API calls (SQL execution, command execution, etc.)
3. **Taint Tracking**: Traced data flow from sources to sinks
4. **Pattern Matching**: Applied vulnerability-specific detection patterns
5. **Validation**: Filtered findings by confidence and severity thresholds

### Limitations

- Only analyzes the provided code, not runtime behavior
- May miss vulnerabilities in dynamically generated code
- False positives possible for complex sanitization patterns
- Does not assess infrastructure or deployment configuration

## Appendix

### A. Complete Rule List

{{#rules}}
| {{rule_id}} | {{cwe}} | {{title}} |
{{/rules}}

### B. Files Analyzed

{{#analyzed_files}}
- `{{file}}` ({{loc}} lines)
{{/analyzed_files}}
