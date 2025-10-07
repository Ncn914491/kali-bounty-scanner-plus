#!/bin/bash
# Safe scanning wrapper (nuclei with conservative settings)

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <target_url>"
    exit 1
fi

TARGET=$1
OUTPUT_DIR="outputs/scan_$(date +%s)"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting safe scan on $TARGET"
echo "[*] Output directory: $OUTPUT_DIR"

# Nuclei with low/medium severity only
if command -v nuclei &> /dev/null; then
    echo "[*] Running Nuclei (low/medium severity)..."
    nuclei -u "$TARGET" \
        -severity low,medium \
        -rate-limit 5 \
        -timeout 20 \
        -retries 1 \
        -json \
        -o "$OUTPUT_DIR/nuclei_results.json"
    
    echo "[+] Nuclei scan complete"
else
    echo "[!] nuclei not found, skipping"
fi

# Nikto with safe flags
if command -v nikto &> /dev/null; then
    echo "[*] Running Nikto (safe mode)..."
    nikto -h "$TARGET" \
        -Format json \
        -output "$OUTPUT_DIR/nikto_results.json" \
        -Tuning 1,2,3 \
        -timeout 20 \
        -maxtime 300 \
        -nointeractive
    
    echo "[+] Nikto scan complete"
else
    echo "[!] nikto not found, skipping"
fi

echo "[+] Safe scan complete"
echo "[+] Results saved to: $OUTPUT_DIR"
