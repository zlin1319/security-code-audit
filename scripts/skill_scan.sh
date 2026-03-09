#!/bin/bash
#
# Dialogue-friendly wrapper for security-code-audit.
# Enables --skill-mode so findings do not surface as shell failures.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_CMD="${PYTHON_CMD:-python3}"

exec "$PYTHON_CMD" "$SCRIPT_DIR/audit.py" --skill-mode "$@"
