#!/bin/bash
# Main pipeline orchestrator script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
MODE="safe-scan"
SCOPE_FILE=""
ALLOW_UNBLOCK=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            TARGET="$2"
            shift 2
            ;;
        --targets-file)
            TARGETS_FILE="$2"
            shift 2
            ;;
        --mode)
            MODE="$2"
            shift 2
            ;;
        --scope-file)
            SCOPE_FILE="$2"
            shift 2
            ;;
        --allow-unblock)
            ALLOW_UNBLOCK=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate inputs
if [ -z "$TARGET" ] && [ -z "$TARGETS_FILE" ]; then
    echo -e "${RED}Error: --target or --targets-file required${NC}"
    exit 1
fi

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Build command
CMD="python3 src/main.py --mode $MODE"

if [ -n "$TARGET" ]; then
    CMD="$CMD --target $TARGET"
fi

if [ -n "$TARGETS_FILE" ]; then
    CMD="$CMD --targets-file $TARGETS_FILE"
fi

if [ -n "$SCOPE_FILE" ]; then
    CMD="$CMD --scope-file $SCOPE_FILE"
fi

if [ "$ALLOW_UNBLOCK" = true ]; then
    CMD="$CMD --allow-unblock"
fi

# Run pipeline
echo -e "${GREEN}Starting pipeline...${NC}"
echo "Command: $CMD"
echo ""

$CMD

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}Pipeline completed successfully${NC}"
else
    echo -e "${RED}Pipeline failed with exit code $EXIT_CODE${NC}"
fi

exit $EXIT_CODE
