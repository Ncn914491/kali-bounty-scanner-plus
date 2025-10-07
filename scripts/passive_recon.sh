#!/bin/bash
# Passive reconnaissance wrapper

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR="outputs/recon_$(date +%s)_${DOMAIN}"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting passive reconnaissance for $DOMAIN"
echo "[*] Output directory: $OUTPUT_DIR"

# Subfinder
echo "[*] Running subfinder..."
if command -v subfinder &> /dev/null; then
    subfinder -d "$DOMAIN" -silent -all -o "$OUTPUT_DIR/subdomains.txt"
    echo "[+] Subfinder complete: $(wc -l < "$OUTPUT_DIR/subdomains.txt") subdomains"
else
    echo "[!] subfinder not found, skipping"
fi

# HTTP probing
if [ -f "$OUTPUT_DIR/subdomains.txt" ]; then
    echo "[*] Probing HTTP services..."
    if command -v httpx &> /dev/null; then
        httpx -l "$OUTPUT_DIR/subdomains.txt" -silent -o "$OUTPUT_DIR/live_hosts.txt"
        echo "[+] HTTP probing complete: $(wc -l < "$OUTPUT_DIR/live_hosts.txt") live hosts"
    else
        echo "[!] httpx not found, skipping"
    fi
fi

echo "[+] Passive reconnaissance complete"
echo "[+] Results saved to: $OUTPUT_DIR"
