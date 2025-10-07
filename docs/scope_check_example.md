# Scope Validation Example

This guide shows how to properly validate and configure scope for a bug bounty program.

## Step 1: Read the Program Policy

Visit the bug bounty program page (e.g., on HackerOne or Bugcrowd) and carefully read:

- **In-Scope Assets**: Domains, subdomains, IPs, applications
- **Out-of-Scope Assets**: Explicitly excluded targets
- **Allowed Testing**: Which vulnerability types are accepted
- **Prohibited Actions**: What you must NOT do
- **Rate Limits**: Maximum requests per second/minute
- **Special Instructions**: Any program-specific rules

## Step 2: Create Your Scope File

Based on the program policy, create a JSON scope file:

```json
{
  "program_name": "Acme Corp Bug Bounty",
  "program_url": "https://hackerone.com/acme-corp",
  "in_scope": [
    "acme.com",
    "*.acme.com",
    "api.acme.com",
    "app.acme.com",
    "192.168.1.0/24"
  ],
  "out_of_scope": [
    "test.acme.com",
    "dev.acme.com",
    "staging.acme.com",
    "internal.acme.com"
  ],
  "notes": [
    "Only test production domains",
    "Rate limit: max 5 requests per second",
    "Do not test admin panel authentication",
    "Report critical findings within 24 hours"
  ],
  "allowed_testing": [
    "XSS",
    "SQL Injection (detection only)",
    "CSRF",
    "IDOR",
    "Authentication bypass",
    "Authorization issues",
    "SSRF",
    "XXE"
  ],
  "prohibited_testing": [
    "DoS/DDoS",
    "Social engineering",
    "Physical attacks",
    "Brute force attacks",
    "Data exfiltration"
  ]
}
```

## Step 3: Validate Your Scope File

Use the policy engine to validate your scope file:

```bash
python3 -c "
from src.policy.policy_engine import PolicyEngine
from src.config import load_config
import json

config = load_config()
engine = PolicyEngine(config)

# Test a target
result = engine.is_target_in_scope('app.acme.com', 'my_scope.json')
print(json.dumps(result, indent=2))
"
```

## Step 4: Test Scope Validation

Before running a full scan, test that your scope file works correctly:

```bash
# Should be ALLOWED
python3 src/main.py --target app.acme.com --mode passive-only --scope-file my_scope.json

# Should be BLOCKED
python3 src/main.py --target test.acme.com --mode passive-only --scope-file my_scope.json
```

## Example: HackerOne Program

Let's say you're testing a HackerOne program with this scope:

**In Scope:**
- `*.example.com`
- `api.example.io`

**Out of Scope:**
- `test.example.com`
- `*.internal.example.com`

**Your scope file:**

```json
{
  "program_name": "Example Corp",
  "program_url": "https://hackerone.com/example-corp",
  "in_scope": [
    "example.com",
    "*.example.com",
    "api.example.io"
  ],
  "out_of_scope": [
    "test.example.com",
    "*.internal.example.com"
  ],
  "notes": [
    "Wildcard *.example.com includes all subdomains except those in out_of_scope",
    "Rate limit: 10 req/s",
    "No automated scanning of authentication endpoints"
  ]
}
```

## Scope Patterns

### Exact Match
```json
"in_scope": ["example.com"]
```
Matches only `example.com`

### Wildcard Subdomain
```json
"in_scope": ["*.example.com"]
```
Matches `app.example.com`, `api.example.com`, etc.

### IP Range (CIDR)
```json
"in_scope": ["192.168.1.0/24"]
```
Matches IPs from 192.168.1.0 to 192.168.1.255

### Multiple Domains
```json
"in_scope": [
  "example.com",
  "example.io",
  "example.net"
]
```

## Common Mistakes

### ❌ Too Broad
```json
"in_scope": ["*"]  // DON'T DO THIS
```

### ❌ Missing Out-of-Scope
```json
{
  "in_scope": ["*.example.com"],
  "out_of_scope": []  // Missing test/dev/staging
}
```

### ❌ Ignoring Program Rules
```json
{
  "allowed_testing": ["DoS"]  // If program prohibits DoS
}
```

## Validation Workflow

```
1. Read program policy
   ↓
2. Create scope file
   ↓
3. Test with passive-only mode
   ↓
4. Verify ALLOWED/BLOCKED decisions
   ↓
5. Adjust scope file if needed
   ↓
6. Run full scan
```

## When Scope is Ambiguous

If you're unsure whether a target is in scope:

1. **Don't test it** - Err on the side of caution
2. **Ask the program** - Contact via the platform
3. **Wait for clarification** - Get written confirmation
4. **Update your scope file** - Add the clarification

## Policy Engine Decisions

The policy engine returns:

- **ALLOWED**: Target matches in-scope patterns, proceed
- **BLOCKED**: Target matches out-of-scope patterns, stop
- **UNKNOWN**: No match found, requires manual confirmation

## Using AI Validation

If Gemini API is configured, the policy engine will:

1. Check local scope file first
2. If no match, consult Gemini for validation
3. Gemini considers program context and best practices
4. Returns decision with confidence score and reasoning

## Best Practices

1. **Be Conservative** - When in doubt, don't test
2. **Document Everything** - Save program rules and your scope file
3. **Test Incrementally** - Start with passive-only mode
4. **Monitor Impact** - Watch for errors or blocks
5. **Update Regularly** - Programs change their scope
6. **Communicate** - Ask questions if unclear

## Example Commands

```bash
# Validate scope only (no scanning)
python3 src/main.py --target example.com --mode passive-only --scope-file my_scope.json

# Safe scan with scope validation
python3 src/main.py --target example.com --mode safe-scan --scope-file my_scope.json

# Full scan with AI validation
python3 src/main.py --target example.com --mode full-scan-with-validation --scope-file my_scope.json
```

## Troubleshooting

### "Target scope UNKNOWN"
- Add the target to your scope file's `in_scope` array
- Or enable `--allow-unblock` with manual confirmation

### "Target BLOCKED"
- Target is in `out_of_scope` - don't test it
- Verify you're testing the correct target

### "No scope file provided"
- Add `--scope-file my_scope.json` to your command
- Create a scope file from the example

## Resources

- [HackerOne Program Policies](https://docs.hackerone.com/programs/)
- [Bugcrowd VDP Guidelines](https://www.bugcrowd.com/resources/guides/vulnerability-disclosure-program-guide/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
