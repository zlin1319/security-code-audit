---
name: security-code-audit
description: Automated security code audit tool that scans repositories for CWE Top 25 and OWASP Top 10 vulnerabilities, outputting structured JSON and human-readable Markdown reports.
---

# Security Code Audit

A comprehensive static application security testing (SAST) skill for auditing code repositories against industry-standard vulnerability databases.

## Skill Execution Rules

For dialogue usage, treat this skill differently from CI:

- For dialogue usage, use `./scripts/skill_scan.sh ...` as the default entrypoint
- Use raw `python -m security_code_audit ...` only for CLI / CI workflows, or when debugging the wrapper itself
- `--skill-mode` automatically enables `--use-ai` and `--auto-ai`
- In skill mode, findings do **not** cause a non-zero shell exit; only real runtime/config failures should
- Never treat scanner exit code `1` or `2` from non-skill mode as a failed execution in the conversation; they mean findings were detected
- Do not rerun the same scan just because the scanner found `high` or `critical` issues
- After a scan completes, immediately read `audit-report.md` and `audit-report-ai.md` if present, then summarize results in the conversation

## Architecture

```text
CLI / Skill Input
        |
        v
Config Load -> Path / Language / Ruleset / Ignore Resolution
        |
        v
File Discovery -> Full Repo or PR/MR Changed Files
        |
        v
Regex Rule Matching (multi-language)
        |
        v
Context Analyzer
- source / sink hints
- sanitizer hints
- confidence adjustment
- inline suppression / ignore filtering
        |
        v
Optional AI Validation (--use-ai / --skill-mode)
        |
        v
Report Writers
- audit-report.json
- audit-report.md
- audit-report.sarif
- audit-report-ai.md
```

### Component Details

**Stage 1: Code Discovery**
- Discover source files from `--path`
- Filter by selected language
- Support full-repo and changed-files scanning

**Stage 2: Static Analysis (SAST)**
- Regex-based rule matching across supported languages
- Rule selection by `--ruleset`
- Confidence threshold filtering by `--confidence`

**Stage 3: Intelligent Validation**
- Local context analysis for source/sink/sanitizer hints
- Ignore file, exclude patterns, and inline suppression support
- Optional AI-enhanced validation when `--use-ai` is enabled
- Dialogue-friendly `--skill-mode` for one-pass scan + AI artifacts

**Stage 4: Report Generation**
- Produces JSON, Markdown, and SARIF outputs
- Optionally produces `audit-report-ai.md` when AI validation is used

## Capabilities

- **Multi-Language Support**: Java, JavaScript/TypeScript, Python, PHP, C#, Kotlin, Go, and extensible to others
- **Rule Coverage**: CWE Top 25, OWASP Top 10, with configurable rule sets
- **Structured Output**: JSON for automation, Markdown for human review
- **SARIF Output**: Native `audit-report.sarif` generation for code scanning uploads
- **Project Config**: Auto-discovery of `.security-audit.toml/.json/.yaml`
- **Ignore/Suppress**: Path ignores plus inline `security-code-audit: ignore <rule_id>`
- **Evidence-Based**: Every finding includes code snippets, reasoning, and fix guidance
- **AI-Enhanced Validation**: Claude Code integration for intelligent false positive filtering

## Quick Start

```bash
# Run audit with defaults (Open Source)
python -m security_code_audit --path /path/to/code --language java

# Dialogue / skill mode (preferred in Claude Code)
./scripts/skill_scan.sh --path /path/to/code --language java

# Specify rule set and output
python -m security_code_audit --path ./myapp --language python --ruleset owasp --output ./reports

# Scan a PHP project
python -m security_code_audit --path ./legacy-app --language php --ruleset all

# Scan a C# project
python -m security_code_audit --path ./dotnet-service --language csharp --ruleset all

# Scan a Kotlin project
python -m security_code_audit --path ./jvm-service --language kotlin --ruleset all

# Generate English report
python -m security_code_audit --path ./src --language java --report-lang en

# PR/MR incremental scan
python -m security_code_audit --path ./src --language go --git-diff-range origin/main...HEAD

# Enterprise mode (requires API key)
python -m security_code_audit --path ./src --language java --api-key YOUR_API_KEY
```

## Parameters

| Parameter | Description | Options | Default |
|-----------|-------------|---------|---------|
| `--path` | Path to code (file or directory) | Any valid path | Required |
| `--language` | Target language | `java`, `javascript`, `typescript`, `python`, `php`, `csharp`, `kotlin`, `go`, `other` | Required |
| `--ruleset` | Rule set to apply | `top25`, `owasp`, `top10`, `all` | `all` |
| `--confidence` | Minimum confidence threshold | `high`, `medium`, `low` | `low` |
| `--config` | Config file path | TOML / JSON / YAML | Auto-discover `.security-audit.*` |
| `--exclude` | Exclude glob patterns | Space-separated globs | None |
| `--ignore-file` | Ignore patterns file | Newline-delimited globs | None |
| `--changed-files` | Only scan specified changed files | Space/comma separated file paths | None |
| `--changed-files-file` | Read changed files from a file | Newline-delimited file paths | None |
| `--git-diff-range` | Only scan files from a git diff range | e.g. `origin/main...HEAD` | None |
| `--output` | Output directory | Any valid path | `reports/<project-name>/` |
| `--skill-mode` | Dialogue-friendly mode: enables AI artifacts and returns exit code 0 for findings | - | False |
| `--report-lang` | Report language | `zh` (Chinese), `en` (English) | `zh` |
| `--auto-ai` | Auto-generate AI analysis prompt | - | False |
| `--api-key` | Enterprise API key for enhanced scanning (SCA, full CWE Top 25) | Your enterprise key | None |

## Open Source vs Enterprise

This tool has two editions:

**Open Source (Default)**
- Basic SAST scanning
- Partial CWE Top 25 coverage
- Community support
- Reports include enterprise upgrade information

**Enterprise (With `--api-key`)**
- Complete CWE Top 25 coverage
- Software Composition Analysis (SCA)
- Advanced vulnerability detection
- Custom rule engine
- Priority support

To upgrade to Enterprise, contact your sales representative for an API key.

## Using with Claude Code (Skill Mode)

When using this skill in Claude Code, do not use the CI-style command path. Use the wrapper so the conversation only needs one scan step and findings do not look like shell failures:

```bash
# Preferred wrapper
./scripts/skill_scan.sh --path ./src --language java --output ./reports

# Raw CLI fallback
python -m security_code_audit --skill-mode --path ./src --language java --output ./reports
```

**Recommended skill prompts:**

```text
Use security-code-audit skill to scan this repository
Use security-code-audit skill to scan ./service with language go
Use security-code-audit skill to only check the current PR/MR changes
Use security-code-audit skill to scan with the project config
```

**Typical command mapping:**

```bash
# Full repository scan
./scripts/skill_scan.sh --path ./src --language other

# Go scan
./scripts/skill_scan.sh --path ./service --language go

# PR/MR incremental scan
./scripts/skill_scan.sh --path ./src --language other --git-diff-range origin/main...HEAD

# Config-driven scan
./scripts/skill_scan.sh --config .security-audit.toml
```

**In skill mode, Claude should automatically:**

1. Run the scan once and do not retry just because findings were returned.
2. Read the generated reports from the output directory.
3. Prefer `audit-report-ai.md` for the AI-filtered view and use `audit-report.md` / `audit-report.json` as supporting evidence.
4. Summarize:
   - true-vs-false-positive judgment
   - highest-risk findings first
   - concrete fixes for the top issues
5. If the wrapper returned successfully, do not present the scan step as failed just because the report contains critical findings.

**Skill mode behavior:**
- Generates `audit-report-ai.md` automatically
- Generates `ai-analysis-prompt.txt` automatically
- Returns shell exit code `0` even when findings exist
- Keeps CI-style non-zero exits available outside skill mode

**Output Files:**
- `audit-report.md` - Standard scan report
- `audit-report-ai.md` - AI deep analysis report
- `audit-report.json` - Machine-readable JSON data
- `audit-report.sarif` - SARIF 2.1.0 report for code scanning platforms

**Manual follow-ups still supported:**
- "AI研判" - Deepen the latest analysis
- "检查误报" - Focus on false positives
- "给出修复代码" - Generate specific fix code for vulnerabilities

## Output Schema

Each vulnerability finding includes:

| Field | Description |
|-------|-------------|
| `rule_id` | Unique rule identifier (e.g., "sqli-001") |
| `cwe` | CWE ID (e.g., "CWE-89") |
| `severity` | Critical/High/Medium/Low |
| `confidence` | High/Medium/Low |
| `file` | Relative file path |
| `line_range` | Affected lines [start, end] |
| `sink_source_summary` | Taint flow summary |
| `evidence_snippet` | Code excerpt with vulnerability |
| `reasoning` | Why this is a vulnerability |
| `fix_guidance` | How to remediate |
| `safe_fix_example` | Secure code example |

## References

- [Vulnerability Rules](references/vulnerability-rules.md) - Complete rule definitions
- [CWE Mapping](references/cwe-mapping.md) - CWE to rule mapping
- [Report Template](assets/report-template.md) - Markdown report template
- [Sample Config](assets/security-audit.toml.example) - Project-level config example
- [Sample Ignore File](assets/security-audit.ignore.example) - Ignore pattern example
- [GitHub Code Scanning Template](assets/ci/github-code-scanning.yml) - GitHub Actions SARIF upload
- [GitLab CI Template](assets/ci/gitlab-ci.yml) - GitLab artifact publishing template
- [Azure Pipelines Template](assets/ci/azure-pipelines.yml) - Azure DevOps SARIF publishing
