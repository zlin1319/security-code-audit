#!/bin/bash
#
# Security Code Audit - Shell Wrapper
# Usage: ./audit.sh <path> <language> [ruleset] [output] [report-lang] [confidence] [extra audit.py args...]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_CMD="${PYTHON_CMD:-python3}"

# Show help
if [ $# -lt 2 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Security Code Audit Tool"
    echo ""
    echo "Usage: $0 <path> <language> [ruleset] [output] [report-lang] [confidence] [extra audit.py args...]"
    echo ""
    echo "Arguments:"
    echo "  path        - Path to code directory or file to audit"
    echo "  language    - Programming language (java|javascript|typescript|python|php|csharp|kotlin|go|other)"
    echo "  ruleset     - Rule set: top25|owasp|top10|all (default: all)"
    echo "  output      - Output directory (default: security-code-audit/reports/<project-name>/)"
    echo "  report-lang - Report language: zh|en (default: zh)"
    echo "  confidence  - Minimum confidence: high|medium|low (default: low)"
    echo "  extra args  - Additional audit.py flags, e.g. --config .security-audit.toml --exclude 'dist/*'"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/java/project java"
    echo "  $0 ./myapp python owasp"
    echo "  $0 ./legacy-app php all"
    echo "  $0 ./dotnet-service csharp all"
    echo "  $0 ./jvm-service kotlin all"
    echo "  $0 ./src javascript top25"
    echo "  $0 ./src java all ./reports en"
    echo "  $0 ./src java all ./reports zh high"
    echo "  $0 ./service go all ./reports zh low --git-diff-range origin/main...HEAD"
    echo ""
    exit 1
fi

TARGET_PATH="$1"
LANGUAGE="$2"
RULESET="${3:-all}"
REPORT_LANG="${5:-zh}"
CONFIDENCE="${6:-low}"
EXTRA_ARGS=("${@:7}")

# Build output path if not provided
if [ -z "$4" ]; then
    # Get project name from target path
    PROJECT_NAME=$(basename "$TARGET_PATH")
    if [ -f "$TARGET_PATH" ]; then
        PROJECT_NAME=$(basename "$TARGET_PATH" | sed 's/\.[^.]*$//')
    fi
    OUTPUT_DIR="$SCRIPT_DIR/../reports/$PROJECT_NAME"
else
    OUTPUT_DIR="$4"
fi

# Validate inputs
if [ ! -e "$TARGET_PATH" ]; then
    echo "Error: Path does not exist: $TARGET_PATH" >&2
    exit 1
fi

case "$LANGUAGE" in
    java|javascript|typescript|python|php|csharp|kotlin|go|other)
        ;;
    *)
        echo "Error: Invalid language: $LANGUAGE" >&2
        echo "Valid options: java, javascript, typescript, python, php, csharp, kotlin, go, other" >&2
        exit 1
        ;;
esac

case "$RULESET" in
    top25|owasp|top10|all)
        ;;
    *)
        echo "Error: Invalid ruleset: $RULESET" >&2
        echo "Valid options: top25, owasp, top10, all" >&2
        exit 1
        ;;
esac

case "$REPORT_LANG" in
    zh|en)
        ;;
    *)
        echo "Error: Invalid report language: $REPORT_LANG" >&2
        echo "Valid options: zh, en" >&2
        exit 1
        ;;
esac

case "$CONFIDENCE" in
    high|medium|low)
        ;;
    *)
        echo "Error: Invalid confidence: $CONFIDENCE" >&2
        echo "Valid options: high, medium, low" >&2
        exit 1
        ;;
esac

# Build command
CMD=(
    "$PYTHON_CMD"
    "$SCRIPT_DIR/audit.py"
    --path "$TARGET_PATH"
    --language "$LANGUAGE"
    --ruleset "$RULESET"
    --report-lang "$REPORT_LANG"
    --confidence "$CONFIDENCE"
)
if [ -n "$4" ]; then
    CMD+=(--output "$OUTPUT_DIR")
    echo "  Output:   $OUTPUT_DIR"
fi
if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
    CMD+=("${EXTRA_ARGS[@]}")
fi

# Run the audit
echo "Starting Security Code Audit..."
echo "  Target:       $TARGET_PATH"
echo "  Language:     $LANGUAGE"
echo "  Ruleset:      $RULESET"
echo "  Report Lang:  $REPORT_LANG"
echo "  Confidence:   $CONFIDENCE"
echo ""

if "${CMD[@]}"; then
    exit_code=0
else
    exit_code=$?
fi

echo ""
if [ $exit_code -eq 0 ]; then
    echo "✓ Audit completed successfully with no critical or high findings"
elif [ $exit_code -eq 1 ]; then
    echo "⚠ Audit completed with high severity findings"
elif [ $exit_code -eq 2 ]; then
    echo "✗ Audit completed with critical findings"
fi

exit $exit_code
