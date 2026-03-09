# Changelog

All notable changes to this project should be documented in this file.

The format follows Keep a Changelog style and this project uses semantic-style version numbers.

## [Unreleased]

### Added
- Proper Python package layout under `security_code_audit/`
- Editable install support via `pip install -e .`
- Console script entrypoint: `security-code-audit`
- Rule baseline tests covering positive and negative cases for each built-in rule
- Ruff and mypy configuration in `pyproject.toml`
- Developer and release documentation

### Changed
- Recommended CLI entrypoint is now `python -m security_code_audit`
- `scripts/audit.py` is now a compatibility wrapper instead of the source-of-truth implementation
- CI templates now use the package entrypoint

## [1.0.0] - 2026-03-09

### Added
- Multi-language local SAST scanning for Java, JavaScript/TypeScript, Python, PHP, C#, Kotlin, and Go
- PR/MR incremental scanning
- SARIF report output
- Config loading, ignore file support, inline suppressions, and optional AI-enhanced validation
