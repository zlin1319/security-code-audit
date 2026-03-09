# Release Guide

## Versioning Policy

Use semantic-style version numbers:

- `MAJOR`: breaking CLI or report-schema changes
- `MINOR`: backward-compatible feature additions
- `PATCH`: backward-compatible fixes, rule tuning, documentation-only corrections

Current source of truth:

- `pyproject.toml` -> `[project].version`
- `security_code_audit/audit.py` -> `__version__`
- `CHANGELOG.md`

Keep these aligned for every release.

## Release Checklist

1. Update version in `pyproject.toml`
2. Update `__version__` in `security_code_audit/audit.py`
3. Move items from `CHANGELOG.md` `Unreleased` into a dated version section
4. Run validation:

```bash
python3 -m py_compile security_code_audit/*.py scripts/audit.py tests/test_smoke.py tests/test_rule_baselines.py
python3 -B -m unittest tests/test_smoke.py tests/test_rule_baselines.py
```

5. If installed locally, verify entrypoints:

```bash
python3 -m security_code_audit --path examples/php/vulnerable_app.php --language php
python3 scripts/audit.py --path examples/go/vulnerable_app.go --language go
./scripts/audit.sh examples/kotlin/VulnerableController.kt kotlin all /tmp/security-code-audit-release-check zh medium
```

6. Review user-facing docs:

- `README.md`
- `SKILL.md`
- `使用场景说明.md`
- `DEVELOPMENT.md`

7. Commit and tag the release

## Notes

- `python -m security_code_audit` is the primary interface
- `scripts/audit.py` and `scripts/audit.sh` must remain functional unless a breaking release explicitly removes them
