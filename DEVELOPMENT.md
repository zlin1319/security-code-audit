# Development Guide

## Overview

This project is now a standard Python package.

- Core package: `security_code_audit/`
- Compatibility entrypoints: `scripts/audit.py`, `scripts/audit.sh`
- Install metadata: `pyproject.toml`

Recommended day-to-day entrypoint:

```bash
python -m security_code_audit --path ./src --language other
```

## Local Setup

### Requirements

- Python `3.11+`
- `pip`

### Editable install

From the repository root:

```bash
python3 -m pip install -e .
```

After that you can use either:

```bash
security-code-audit --path ./src --language java
```

or:

```bash
python3 -m security_code_audit --path ./src --language java
```

### Optional dependency

YAML config support requires `PyYAML`:

```bash
python3 -m pip install pyyaml
```

Without `PyYAML`, TOML and JSON configs still work.

## Repository Layout

```text
security_code_audit/
├── audit.py              # Main CLI and scan orchestration
├── rules.py              # Language patterns and rule metadata
├── config_loader.py      # Config discovery and parsing
├── suppressions.py       # Ignore file / inline suppress helpers
├── context_analyzer.py   # Confidence and source/sink heuristics
├── ai_analyzer.py        # Optional AI-enhanced validation
├── __init__.py
└── __main__.py
```

Supporting directories:

- `tests/`: smoke tests
- `examples/`: sample vulnerable code for demos and regression checks
- `assets/`: templates, schemas, CI examples
- `references/`: vulnerability mapping/reference material
- `scripts/`: compatibility wrappers only

## Common Commands

### Run the CLI

```bash
python3 -m security_code_audit --path examples/php/vulnerable_app.php --language php
```

### Run smoke tests

```bash
python3 -B -m unittest tests/test_smoke.py
```

### Compile-check package files

```bash
python3 -m py_compile security_code_audit/*.py scripts/audit.py tests/test_smoke.py
```

## Making Changes

### Add or update a rule

Edit:

- `security_code_audit/rules.py`

Keep these in sync:

- language patterns
- extensions mapping
- supported language list
- rule metadata if a new rule is added

If behavior changes, update:

- `examples/` if a sample is needed
- `tests/test_smoke.py` if the CLI contract changes
- `README.md` / `使用场景说明.md` if user-facing usage changes

### Add a new language

Minimum required updates:

1. `security_code_audit/rules.py`
2. `security_code_audit/context_analyzer.py`
3. `README.md`
4. `SKILL.md`
5. `使用场景说明.md`
6. `examples/`
7. `tests/test_smoke.py`

### Change CLI behavior

Primary file:

- `security_code_audit/audit.py`

Check these after changes:

- package entrypoint: `python -m security_code_audit`
- compatibility wrapper: `python scripts/audit.py`
- shell wrapper: `./scripts/audit.sh`
- smoke tests

## Compatibility Policy

Current intended behavior:

- `python -m security_code_audit` is the primary interface
- `scripts/audit.py` remains as a backward-compatible wrapper
- `scripts/audit.sh` remains as a shell convenience wrapper

Do not move core logic back into `scripts/`.

## Documentation Checklist

When changing behavior, review:

- `README.md`
- `SKILL.md`
- `使用场景说明.md`
- CI templates under `assets/ci/`

The package layout and the recommended CLI should stay consistent across all of them.

For version bumps and release steps, see `RELEASE.md`.
