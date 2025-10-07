#!/bin/bash
# HTTP probing wrapper

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <targets_file>"
    exit 1
fi

TARGETS_FILE=$1
OUTPUT_FILE="outputs/http_probe_$(date +%s).txt"

echo "[*] Probing HTTP services from $TARGETS_FILE"

if ! command -v httpx &> /dev/null; then
    echo "[!] httpx not found. Install with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    exit 1
fi

# Conservative httpx settings
httpx -l "$TARGETS_FILE" \
    -silent \
    -threads 10 \
    -timeout 20 \
    -status-code \
    -title \
    -tech-detect \
    -o "$OUTPUT_FILE"

echo "[+] HTTP probing complete"
echo "[+] Results saved to: $OUTPUT_FILE"
echo "[+] Found $(wc -l < "$OUTPUT_FILE") live hosts"
