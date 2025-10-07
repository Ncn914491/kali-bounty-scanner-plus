# Ethics & Legal Guidelines

## ⚠️ Critical Legal Notice

**UNAUTHORIZED ACCESS TO COMPUTER SYSTEMS IS ILLEGAL**

This tool is designed exclusively for authorized security testing. Using it without explicit permission is:
- **Illegal** under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide
- **Unethical** and harmful to the security community
- **Punishable** by fines and imprisonment

## Before You Scan

### Required Steps

1. **Obtain Written Permission**
   - Get explicit authorization from the system owner
   - For bug bounty programs, read and understand the program rules
   - Save a copy of the authorization/program rules

2. **Verify Scope**
   - Confirm which domains/IPs are in-scope
   - Identify explicitly out-of-scope targets
   - Understand testing limitations (e.g., no DoS, no social engineering)

3. **Configure Your Scope File**
   - Create a scope file based on the program rules
   - Use `examples/in_scope.example.json` as a template
   - Be conservative - when in doubt, ask the program owner

4. **Understand Rate Limits**
   - Respect the program's rate limit requirements
   - Configure `SCAN_RATE` in `.env` appropriately
   - Monitor your scan's impact on the target

5. **Review Prohibited Actions**
   - Never perform DoS/DDoS attacks
   - Don't access or exfiltrate user data
   - Avoid destructive testing
   - Don't test on production systems unless explicitly allowed

## Bug Bounty Program Checklist

Before starting a bug bounty scan:

- [ ] I have read the program's policy page completely
- [ ] I have created a scope file with in-scope and out-of-scope targets
- [ ] I understand which vulnerability types are accepted
- [ ] I know the program's rate limit requirements
- [ ] I have configured my `.env` file with appropriate limits
- [ ] I understand the program's disclosure policy
- [ ] I will not test prohibited vulnerability types
- [ ] I will report findings responsibly and promptly

## Responsible Disclosure

### When You Find a Vulnerability

1. **Stop Testing** - Don't exploit the vulnerability further
2. **Document Carefully** - Record steps to reproduce
3. **Report Promptly** - Submit through the program's official channel
4. **Don't Disclose Publicly** - Wait for the vendor to fix the issue
5. **Follow Up** - Respond to questions from the triage team

### What NOT to Do

- ❌ Don't access user data or PII
- ❌ Don't modify or delete data
- ❌ Don't pivot to other systems
- ❌ Don't share findings publicly before disclosure
- ❌ Don't use findings for personal gain
- ❌ Don't continue testing after finding critical issues

## Tool Safety Features

This tool includes multiple safety mechanisms:

1. **Policy Engine** - Blocks high-risk actions by default
2. **AI Validation** - Uses Gemini to evaluate ambiguous actions
3. **Rate Limiting** - Prevents overwhelming target systems
4. **Audit Trail** - Logs all actions for accountability
5. **Manual Confirmation** - Requires explicit approval for risky actions

## Ethical Principles

### Do:
- ✅ Test only authorized targets
- ✅ Respect rate limits and system resources
- ✅ Report findings responsibly
- ✅ Help improve security
- ✅ Follow program rules exactly
- ✅ Be professional and courteous

### Don't:
- ❌ Test without permission
- ❌ Cause harm or disruption
- ❌ Access sensitive data
- ❌ Extort or threaten
- ❌ Disclose vulnerabilities prematurely
- ❌ Use findings maliciously

## Legal Resources

- [HackerOne Disclosure Guidelines](https://www.hackerone.com/disclosure-guidelines)
- [Bugcrowd Vulnerability Disclosure Policy](https://www.bugcrowd.com/resource/what-is-responsible-disclosure/)
- [CFAA Overview](https://www.justice.gov/criminal-ccips/computer-fraud-and-abuse-act)

## Questions?

If you're unsure whether an action is authorized:
1. **Stop** - Don't proceed
2. **Ask** - Contact the program owner
3. **Wait** - Get explicit clarification
4. **Document** - Save the response

**When in doubt, don't test.**

## Disclaimer

The authors of this tool are not responsible for misuse. You are solely responsible for ensuring you have proper authorization before using this tool.

This tool is provided "as is" without warranty. Use at your own risk.
