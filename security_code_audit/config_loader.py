#!/usr/bin/env python3
"""
Configuration loading for the security audit tool.
Supports TOML/JSON natively and YAML when PyYAML is installed.
"""

import json
import tomllib
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_CONFIG_NAMES = [
    ".security-audit.toml",
    ".security-audit.json",
    ".security-audit.yaml",
    ".security-audit.yml",
]


def _parse_yaml(path: Path) -> Dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(
            f"YAML config requested but PyYAML is not installed: {path}"
        ) from exc

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config root must be a mapping: {path}")
    return data


def load_config(config_path: Optional[str], target_path: str) -> Dict[str, Any]:
    """Load explicit or discovered configuration for the target path."""
    discovered = None
    if config_path:
        discovered = Path(config_path).resolve()
    else:
        candidate_roots = []
        target = Path(target_path).resolve()
        candidate_roots.append(target if target.is_dir() else target.parent)
        candidate_roots.append(Path.cwd())

        seen = set()
        for root in candidate_roots:
            root = root.resolve()
            if root in seen:
                continue
            seen.add(root)
            for name in DEFAULT_CONFIG_NAMES:
                candidate = root / name
                if candidate.exists():
                    discovered = candidate
                    break
            if discovered:
                break

    if discovered is None:
        return {}

    suffix = discovered.suffix.lower()
    if suffix == ".toml":
        with discovered.open("rb") as f:
            data = tomllib.load(f)
    elif suffix == ".json":
        with discovered.open("r", encoding="utf-8") as f:
            data = json.load(f)
    elif suffix in {".yaml", ".yml"}:
        data = _parse_yaml(discovered)
    else:
        raise ValueError(f"Unsupported config format: {discovered}")

    if not isinstance(data, dict):
        raise ValueError(f"Config root must be a mapping: {discovered}")

    if isinstance(data.get("scan"), dict):
        merged = data["scan"].copy()
        for key, value in data.items():
            if key == "scan":
                continue
            merged.setdefault(key, value)
        data = merged

    data["__config_path__"] = str(discovered)
    data["__config_dir__"] = str(discovered.parent)
    return data


def merge_cli_with_config(cli_value: Any, config: Dict[str, Any], key: str, default: Any = None) -> Any:
    """Prefer CLI values, then config, then default."""
    if cli_value is not None:
        return cli_value
    if key in config:
        return config[key]
    return default
