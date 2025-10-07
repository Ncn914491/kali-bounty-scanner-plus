# Kali Bounty Scanner Plus

[![CI](https://github.com/Ncn914491/kali-bounty-scanner-plus/workflows/CI/badge.svg)](https://github.com/Ncn914491/kali-bounty-scanner-plus/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

**A robust, modular, AI-driven reconnaissance and vulnerability discovery toolkit for ethical bug bounty hunting.**

## ⚠️ Legal & Ethical Notice

**USE ONLY ON TARGETS YOU HAVE EXPLICIT PERMISSION TO TEST.**

This tool is designed for authorized security testing on bug bounty programs (HackerOne, Bugcrowd, etc.) where you have explicit permission. Unauthorized testing is illegal and unethical.

- The tool includes an AI-powered policy validator that blocks out-of-scope or high-risk actions
- All destructive actions are disabled by default
- Manual confirmation is required for any potentially risky operations
- All actions are logged for audit purposes

**You are responsible for ensuring you have permission before scanning any target.**

## Features

- **AI-Driven Policy Validation**: Gemini LLM validates every action against scope and safety rules
- **Conservative Defaults**: Rate-limited, timeout-protected, non-destructive scanning
- **Modular Pipeline**: Passive recon → HTTP probing → Safe scanning → AI triage → Report generation
- **Explainable Triage**: ML + LLM fusion scoring with detailed rationale
- **HackerOne-Ready Reports**: Auto-generated professional vulnerability reports
- **Audit Trail**: All decisions and actions logged to SQLite
- **Blocklist System**: High-risk templates blocked by default with manual override flow

## Quick Start

### 1. Install Dependencies

```bash
# Clone and enter directory
cd kali-bounty-scanner-plus

# Run installer (checks for required tools)
chmod +x install.sh
./install.sh
```

### 2. Configure Environment

```bash
# Copy template and edit with your settings
cp .env.template .env
nano .env
```

**Required**: Add your Gemini API key to `.env`:
```
GEMINI_API_KEY=your_key_here
```

**Get a Gemini API Key**:
1. Visit https://makersuite.google.com/app/apikey
2. Sign in with Google account
3. Click "Create API Key"
4. Copy key to `.env` file

### 3. Define Your Scope

Create a scope file for your target program:

```bash
cp examples/in_scope.example.json my_program_scope.json
# Edit with actual in-scope domains/IPs from your bug bounty program
```

### 4. Run a Scan

```bash
# Passive reconnaissance only (safest)
python3 src/main.py --target example.com --mode passive-only

# Safe scanning with policy validation
python3 src/main.py --target example.com --mode safe-scan --scope-file my_program_scope.json

# Full pipeline with AI validation
python3 src/main.py --target example.com --mode full-scan-with-validation --scope-file my_program_scope.json
```

## How the Policy Validator Works

The policy engine operates in layers:

1. **Local Blocklist**: High-risk templates (RCE, SQLi exploits) are blocked by default
2. **Scope Validation**: Target is checked against your defined scope file
3. **AI Validation**: Gemini LLM evaluates ambiguous actions and provides reasoning
4. **Manual Override**: Blocked actions can be manually approved with explicit confirmation

**Decision Types**:
- `ALLOWED`: Action proceeds automatically
- `BLOCKED`: Action is refused (logged)
- `UNKNOWN`: Insufficient scope information (scan stops)
- `REQUIRES_VALIDATION`: Sent to Gemini for evaluation

## Architecture

```
src/
├── main.py              # CLI entry point
├── orchestrator.py      # Pipeline coordinator
├── config.py            # Configuration loader
├── scanners/            # Tool wrappers (nuclei, nikto, ffuf, crawler)
├── recon/               # Passive recon & port scanning
├── triage/              # ML + LLM scoring engine
├── policy/              # Policy engine & Gemini validator
├── reports/             # Report generator with templates
├── db/                  # SQLite storage
├── utils/               # Logging, rate limiting, sanitization
└── integrations/        # Gemini API client
```

## Scan Modes

- **passive-only**: Subdomain enumeration, DNS, no active probing
- **safe-scan**: HTTP probing + low/medium severity nuclei templates
- **full-scan-with-validation**: All tools with AI policy checks

## Output

Results are saved to `./outputs/<timestamp>_<target>/`:
- `recon.json` - Discovered assets
- `findings.json` - Vulnerability findings
- `report.md` - HackerOne-ready report
- `audit.log` - All policy decisions

## Ethics Checklist

Before scanning:
- [ ] I have explicit permission from the program owner
- [ ] I have read the program's scope and rules
- [ ] I have configured my scope file correctly
- [ ] I understand this tool logs all my actions
- [ ] I will not use blocked templates without valid justification

## Development

```bash
# Setup dev environment
./scripts/dev_bootstrap.sh

# Run tests
python3 -m pytest tests/

# Train triage model on your data
python3 src/triage/model_train.py --data your_labeled_data.json
```

## Configuration Options

See `.env.template` for all options:
- `SCAN_RATE`: Requests per minute (default: 5)
- `MAX_CONCURRENCY`: Parallel tasks (default: 4)
- `TIMEOUT`: Request timeout in seconds (default: 20)
- `ALLOW_MANUAL_UNBLOCK`: Enable manual override flow (default: false)
- `STORE_LLM_RESPONSES`: Log AI responses for audit (default: true)

## Troubleshooting

**"Policy engine returned UNKNOWN"**: Define your scope file with `--scope-file`

**"Gemini API key not found"**: Add `GEMINI_API_KEY` to `.env`

**"Template blocked by policy"**: Review `policy/blocked_manifest.json` or use `--allow-unblock` with manual confirmation

## License

MIT License - See LICENSE file

## Contributing

Contributions welcome! Please ensure all new scanners include policy validation hooks and maintain conservative defaults.

## Disclaimer

This tool is for authorized security testing only. The authors are not responsible for misuse. Always obtain explicit written permission before testing any system.
