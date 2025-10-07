# Example Run

This document demonstrates a typical scan workflow.

## Setup

```bash
# Copy and configure environment
cp .env.template .env
nano .env  # Add GEMINI_API_KEY

# Create scope file
cp examples/in_scope.example.json my_scope.json
# Edit my_scope.json with your program's actual scope
```

## Passive Reconnaissance Only

```bash
python3 src/main.py --target example.com --mode passive-only
```

**Expected Output:**
```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        Kali Bounty Scanner Plus v1.0                      ║
║        AI-Driven Ethical Bug Bounty Toolkit               ║
║                                                           ║
║  ⚠️  USE ONLY ON AUTHORIZED TARGETS                       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

[INFO] Configuration loaded successfully
[INFO] Database initialized
[INFO] Starting pipeline for example.com (mode: passive-only, run_id: 1234567890_example_com)
[INFO] Step 1: Validating target scope...
[WARN] Target scope UNKNOWN: No scope file provided
[ERROR] Scan aborted. Provide --scope-file or enable manual unblock.
```

## Safe Scan with Scope File

```bash
python3 src/main.py --target example.com --mode safe-scan --scope-file my_scope.json
```

**Expected Output:**
```
[INFO] Step 1: Validating target scope...
[INFO] ✓ Target scope validated: ALLOWED
[INFO] Step 2: Running passive reconnaissance...
[INFO] Enumerating subdomains for example.com
[INFO] Subfinder found 15 subdomains
[INFO] Probing 15 subdomains for HTTP services
[INFO] Found 8 live HTTP services
[INFO] ✓ Recon complete. Found 15 subdomains
[INFO] Step 3: Probing HTTP services...
[INFO] ✓ Found 8 live hosts
[INFO] Step 4: Crawling web applications...
[INFO] Crawling https://example.com (max_depth=3, max_pages=50)
[INFO] Crawled 25 pages
[INFO] ✓ Crawled 25 URLs
[INFO] Step 5: Running safe vulnerability scans...
[INFO] Running Nuclei scan on https://example.com (severity: low,medium)
[INFO] Nuclei found 3 potential issues
[INFO] ✓ Scan complete. Found 3 potential findings
[INFO] Step 6: Running AI triage on findings...
[INFO] Calling Gemini API (temp=0.2, max_tokens=400)
[INFO] Gemini API call successful
[INFO] Triaged finding: Missing Security Headers - Score: 0.45
[INFO] ✓ Triage complete. 3 findings scored
[INFO] Step 7: Generating HackerOne-ready report...
[INFO] Generating report for example.com
[INFO] Report saved to outputs/1234567890_example_com/report.md
[INFO] ✓ Report generated: outputs/1234567890_example_com/report.md

============================================================
Pipeline complete for example.com
Duration: 45.3s
Findings: 3
Output: outputs/1234567890_example_com
============================================================
```

## Blocked Action Example

```bash
# Try to scan with a blocked template
python3 src/main.py --target example.com --mode full-scan-with-validation --scope-file my_scope.json
```

**Expected Output (if blocked template detected):**
```
[INFO] Step 5: Running safe vulnerability scans...
[INFO] Validating scanner action: nuclei on https://example.com
[WARN] Scan blocked for https://example.com: Template matches blocked pattern: rce-templates
[INFO] ✓ Scan complete. Found 2 potential findings
```

## Manual Override Flow

```bash
# Enable manual override
python3 src/main.py --target unknown-target.com --mode safe-scan --allow-unblock
```

**Expected Output:**
```
[INFO] Step 1: Validating target scope...
[WARN] Target scope UNKNOWN: Target does not match any scope patterns

============================================================
⚠️  MANUAL OVERRIDE REQUIRED
============================================================
Target: unknown-target.com
Reason: Target does not match any scope patterns

This target's scope could not be automatically validated.
Proceeding requires explicit confirmation that you have permission.

Type 'I_ACCEPT_RISK' to continue, or anything else to abort:
============================================================
> I_ACCEPT_RISK

[WARN] Manual override accept