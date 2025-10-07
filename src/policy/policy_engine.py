"""
Policy engine with local rules and Gemini LLM validation.

This module enforces ethical and legal constraints by:
1. Checking local blocklist for high-risk actions
2. Validating target scope against program rules
3. Using Gemini LLM for ambiguous decisions
4. Logging all decisions for audit
"""

import json
import re
from pathlib import Path

from integrations.gemini_client import GeminiClient
from utils.logger import log_info, log_warning, log_error
from db.storage import log_policy_decision


class PolicyEngine:
    """Policy engine for validating targets and scanner actions."""
    
    def __init__(self, config):
        """
        Initialize policy engine.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self.gemini_client = GeminiClient(config)
        self.blocked_manifest = self._load_blocked_manifest()
    
    def _load_blocked_manifest(self):
        """Load blocked actions manifest."""
        manifest_path = Path(__file__).parent / 'blocked_manifest.json'
        
        if not manifest_path.exists():
            log_warning("Blocked manifest not found, using defaults")
            return self._get_default_manifest()
        
        try:
            with open(manifest_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            log_error(f"Failed to load blocked manifest: {e}")
            return self._get_default_manifest()
    
    def _get_default_manifest(self):
        """Get default blocked actions manifest."""
        return {
            'blocked_patterns': [
                {
                    'id': 'rce-templates',
                    'pattern': r'(rce|remote[-_]?exec|command[-_]?injection)',
                    'default_action': 'BLOCK',
                    'notes': 'Remote code execution - high risk'
                },
                {
                    'id': 'sql-exploit',
                    'pattern': r'(sqlmap|sql[-_]?injection[-_]?exploit)',
                    'default_action': 'BLOCK',
                    'notes': 'SQL exploitation tools - requires manual approval'
                },
                {
                    'id': 'file-upload-exec',
                    'pattern': r'(upload[-_]?exec|webshell)',
                    'default_action': 'BLOCK',
                    'notes': 'File upload exploitation - destructive'
                },
                {
                    'id': 'dos-attacks',
                    'pattern': r'(dos|denial[-_]?of[-_]?service|slowloris)',
                    'default_action': 'BLOCK',
                    'notes': 'Denial of service - always blocked'
                }
            ],
            'requires_validation': [
                {
                    'id': 'auth-bypass',
                    'pattern': r'(auth[-_]?bypass|authentication)',
                    'notes': 'Authentication testing - validate scope'
                },
                {
                    'id': 'file-inclusion',
                    'pattern': r'(lfi|rfi|file[-_]?inclusion)',
                    'notes': 'File inclusion - validate if read-only'
                }
            ]
        }
    
    def is_target_in_scope(self, target, scope_file=None):
        """
        Validate if target is in scope for testing.
        
        Args:
            target (str): Target domain or IP
            scope_file (str): Path to scope definition file
        
        Returns:
            dict: Decision with keys: decision, confidence, reason, details
        """
        log_info(f"Validating scope for target: {target}")
        
        # If no scope file provided, return UNKNOWN
        if not scope_file:
            decision = {
                'decision': 'UNKNOWN',
                'confidence': 0.0,
                'reason': 'No scope file provided',
                'details': 'Provide --scope-file with in-scope targets from your bug bounty program'
            }
            log_policy_decision(target, 'scope_check', decision['decision'], 
                              decision['reason'], decision['confidence'])
            return decision
        
        # Load scope file
        try:
            with open(scope_file, 'r') as f:
                scope_data = json.load(f)
        except Exception as e:
            decision = {
                'decision': 'UNKNOWN',
                'confidence': 0.0,
                'reason': f'Failed to load scope file: {e}',
                'details': 'Check scope file format'
            }
            log_policy_decision(target, 'scope_check', decision['decision'],
                              decision['reason'], decision['confidence'])
            return decision
        
        # Check if target matches in-scope patterns
        in_scope = scope_data.get('in_scope', [])
        out_of_scope = scope_data.get('out_of_scope', [])
        
        # Check out-of-scope first (explicit blocks)
        for pattern in out_of_scope:
            if self._matches_pattern(target, pattern):
                decision = {
                    'decision': 'BLOCKED',
                    'confidence': 1.0,
                    'reason': f'Target matches out-of-scope pattern: {pattern}',
                    'details': 'This target is explicitly excluded from the program scope'
                }
                log_policy_decision(target, 'scope_check', decision['decision'],
                                  decision['reason'], decision['confidence'])
                return decision
        
        # Check in-scope patterns
        for pattern in in_scope:
            if self._matches_pattern(target, pattern):
                decision = {
                    'decision': 'ALLOWED',
                    'confidence': 1.0,
                    'reason': f'Target matches in-scope pattern: {pattern}',
                    'details': 'Target is within defined program scope'
                }
                log_policy_decision(target, 'scope_check', decision['decision'],
                                  decision['reason'], decision['confidence'])
                return decision
        
        # No match - use Gemini for validation if available
        if self.config.get('GEMINI_API_KEY'):
            log_info("No direct scope match, consulting Gemini for validation...")
            gemini_decision = self._validate_scope_with_gemini(target, scope_data)
            log_policy_decision(target, 'scope_check_gemini', gemini_decision['decision'],
                              gemini_decision['reason'], gemini_decision['confidence'])
            return gemini_decision
        
        # No Gemini, return UNKNOWN
        decision = {
            'decision': 'UNKNOWN',
            'confidence': 0.0,
            'reason': 'Target does not match any scope patterns',
            'details': 'Add target to scope file or enable Gemini validation'
        }
        log_policy_decision(target, 'scope_check', decision['decision'],
                          decision['reason'], decision['confidence'])
        return decision
    
    def validate_scanner_action(self, action_descriptor):
        """
        Validate if a scanner action is allowed.
        
        Args:
            action_descriptor (dict): Action details (scanner, target, template, etc.)
        
        Returns:
            dict: Decision with keys: decision, confidence, reason, details
        """
        scanner = action_descriptor.get('scanner', 'unknown')
        template = action_descriptor.get('template', '')
        target = action_descriptor.get('target', '')
        
        log_info(f"Validating scanner action: {scanner} on {target}")
        
        # Check blocked patterns
        for blocked in self.blocked_manifest.get('blocked_patterns', []):
            pattern = blocked['pattern']
            if re.search(pattern, template, re.IGNORECASE):
                decision = {
                    'decision': 'BLOCKED',
                    'confidence': 1.0,
                    'reason': f"Template matches blocked pattern: {blocked['id']}",
                    'details': blocked['notes']
                }
                log_policy_decision(target, f'scanner_{scanner}', decision['decision'],
                                  decision['reason'], decision['confidence'])
                return decision
        
        # Check if requires validation
        for validation_rule in self.blocked_manifest.get('requires_validation', []):
            pattern = validation_rule['pattern']
            if re.search(pattern, template, re.IGNORECASE):
                decision = {
                    'decision': 'REQUIRES_VALIDATION',
                    'confidence': 0.5,
                    'reason': f"Template requires validation: {validation_rule['id']}",
                    'details': validation_rule['notes']
                }
                
                # If Gemini available, validate now
                if self.config.get('GEMINI_API_KEY'):
                    gemini_decision = self._validate_action_with_gemini(action_descriptor)
                    log_policy_decision(target, f'scanner_{scanner}_gemini',
                                      gemini_decision['decision'],
                                      gemini_decision['reason'],
                                      gemini_decision['confidence'])
                    return gemini_decision
                
                log_policy_decision(target, f'scanner_{scanner}', decision['decision'],
                                  decision['reason'], decision['confidence'])
                return decision
        
        # Default: ALLOWED
        decision = {
            'decision': 'ALLOWED',
            'confidence': 1.0,
            'reason': 'No policy restrictions matched',
            'details': 'Action is within safe parameters'
        }
        return decision
    
    def _matches_pattern(self, target, pattern):
        """
        Check if target matches a scope pattern.
        
        Args:
            target (str): Target to check
            pattern (str): Pattern (domain, wildcard, or regex)
        
        Returns:
            bool: True if matches
        """
        # Exact match
        if target == pattern:
            return True
        
        # Wildcard match (*.example.com)
        if pattern.startswith('*.'):
            domain_suffix = pattern[2:]
            if target.endswith(domain_suffix) or target == domain_suffix:
                return True
        
        # Subdomain match
        if target.endswith('.' + pattern):
            return True
        
        return False
    
    def _validate_scope_with_gemini(self, target, scope_data):
        """
        Use Gemini to validate target scope.
        
        Args:
            target (str): Target to validate
            scope_data (dict): Scope definition
        
        Returns:
            dict: Decision from Gemini
        """
        system_prompt = """You are a strict security policy assistant for bug bounty programs.
Your role is to determine if a target is within the scope of a security testing program.

Respond ONLY with valid JSON in this exact format:
{
  "decision": "ALLOWED" or "BLOCKED" or "UNKNOWN",
  "confidence": 0.0 to 1.0,
  "reasons": ["reason1", "reason2"],
  "suggested_next_steps": ["step1", "step2"]
}

Rules:
- ALLOWED: Target clearly matches in-scope patterns
- BLOCKED: Target clearly matches out-of-scope patterns or is high-risk
- UNKNOWN: Insufficient information to make determination
- Never suggest evasive or destructive actions
- Be conservative - when in doubt, return UNKNOWN"""
        
        user_prompt = f"""Target: {target}

In-Scope Patterns: {json.dumps(scope_data.get('in_scope', []))}
Out-of-Scope Patterns: {json.dumps(scope_data.get('out_of_scope', []))}

Is this target within scope for security testing?"""
        
        try:
            response = self.gemini_client.call_gemini(
                prompt=user_prompt,
                system_prompt=system_prompt,
                max_tokens=500,
                temperature=0.1
            )
            
            # Parse JSON response
            result = json.loads(response)
            
            return {
                'decision': result.get('decision', 'UNKNOWN'),
                'confidence': result.get('confidence', 0.0),
                'reason': '; '.join(result.get('reasons', ['Gemini validation'])),
                'details': '; '.join(result.get('suggested_next_steps', []))
            }
            
        except Exception as e:
            log_error(f"Gemini validation failed: {e}")
            return {
                'decision': 'UNKNOWN',
                'confidence': 0.0,
                'reason': f'Gemini validation error: {e}',
                'details': 'Manual review required'
            }
    
    def _validate_action_with_gemini(self, action_descriptor):
        """
        Use Gemini to validate a scanner action.
        
        Args:
            action_descriptor (dict): Action details
        
        Returns:
            dict: Decision from Gemini
        """
        system_prompt = """You are a security policy validator for ethical bug bounty testing.
Evaluate if a proposed scanner action is safe and appropriate.

Respond ONLY with valid JSON:
{
  "decision": "ALLOWED" or "BLOCKED",
  "confidence": 0.0 to 1.0,
  "reasons": ["reason1"],
  "risk_level": "low" or "medium" or "high"
}

BLOCK if:
- Action could cause damage or disruption
- Action involves exploitation (not just detection)
- Action is outside typical bug bounty scope

ALLOW if:
- Action is read-only or passive
- Action is standard vulnerability detection
- Risk is low and within ethical bounds"""
        
        user_prompt = f"""Scanner Action:
Scanner: {action_descriptor.get('scanner')}
Target: {action_descriptor.get('target')}
Template: {action_descriptor.get('template', 'N/A')}
Severity: {action_descriptor.get('severity', 'N/A')}

Should this action be allowed?"""
        
        try:
            response = self.gemini_client.call_gemini(
                prompt=user_prompt,
                system_prompt=system_prompt,
                max_tokens=400,
                temperature=0.1
            )
            
            result = json.loads(response)
            
            return {
                'decision': result.get('decision', 'BLOCKED'),
                'confidence': result.get('confidence', 0.0),
                'reason': '; '.join(result.get('reasons', ['Gemini validation'])),
                'details': f"Risk level: {result.get('risk_level', 'unknown')}"
            }
            
        except Exception as e:
            log_error(f"Gemini action validation failed: {e}")
            # Fail closed - block on error
            return {
                'decision': 'BLOCKED',
                'confidence': 0.0,
                'reason': f'Validation error: {e}',
                'details': 'Failed to validate, blocking for safety'
            }
