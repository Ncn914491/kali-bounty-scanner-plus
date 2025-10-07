# Usage Guide

## Quick Start

```bash
# 1. Install
./install.sh

# 2. Configure
cp .env.template .env
nano .env  # Add GEMINI_API_KEY

# 3. Define scope
cp examples/in_scope.example.json my_scope.json

# 4. Run scan
python3 src/main.py --target example.com --mode safe-scan --scope-file my_scope.json
```

## Scan Modes

**passive-only**: Subdomain enumeration only (safest)
**safe-scan**: Low/medium severity scanning (recommended)
**full-scan-with-validation**: Complete scanning with AI validation

## Examples

```bash
# Passive recon
python3 src/main.py --target example.com --mode passive-only

# Safe scan with scope
python3 src/main.py --target example.com --mode safe-scan --scope-file my_scope.json

# Multiple targets
python3 src/main.py --targets-file targets.txt --mode safe-scan --scope-file my_scope.json
```

See README.md for full documentation.
