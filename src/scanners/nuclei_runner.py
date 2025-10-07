"""Nuclei scanner wrapper with template whitelisting."""

import subprocess
import json
import tempfile
from pathlib import Path

from utils.logger import log_info, log_warning, log_error
from utils.sanitizer import sanitize_url
from utils.rate_limiter import RateLimiter


class NucleiRunner:
    """Nuclei vulnerability scanner with policy-controlled templates."""
    
    def __init__(self, config):
        """
        Initialize Nuclei runner.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self.rate_limiter = RateLimiter(
            rate_per_minute=config['NUCLEI_RATE_LIMIT'],
            max_concurrency=config['NUCLEI_CONCURRENCY']
        )
        self.whitelist_file = Path('policy/whitelist_templates.txt')
    
    def run(self, target, severity=None, templates=None):
        """
        Run Nuclei scan on target.
        
        Args:
            target (str): Target URL
            severity (list): List of severity levels (e.g., ['low', 'medium'])
            templates (list): Specific templates to run
        
        Returns:
            list: List of findings
        """
        target = sanitize_url(target)
        if not target:
            log_error(f"Invalid target URL: {target}")
            return []
        
        if severity is None:
            severity = ['low', 'medium']
        
        log_info(f"Running Nuclei scan on {target} (severity: {','.join(severity)})")
        
        try:
            # Build nuclei command
            cmd = [
                'nuclei',
                '-u', target,
                '-silent',
                '-json',
                '-rate-limit', str(self.config['NUCLEI_RATE_LIMIT']),
                '-timeout', str(self.config['TIMEOUT']),
                '-retries', '1'
            ]
            
            # Add severity filter
            if severity:
                cmd.extend(['-severity', ','.join(severity)])
            
            # Add template filter if whitelist exists
            if self.whitelist_file.exists():
                cmd.extend(['-t', str(self.whitelist_file)])
            
            # Run with rate limiting
            with self.rate_limiter:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
            
            if result.returncode == 0 or result.stdout:
                findings = self._parse_nuclei_output(result.stdout, target)
                log_info(f"Nuclei found {len(findings)} potential issues")
                return findings
            else:
                log_warning(f"Nuclei scan completed with no findings")
                return []
                
        except FileNotFoundError:
            log_warning("nuclei not found, skipping scan")
            return []
        except subprocess.TimeoutExpired:
            log_warning(f"Nuclei scan timed out for {target}")
            return []
        except Exception as e:
            log_error(f"Nuclei scan failed: {e}")
            return []
    
    def _parse_nuclei_output(self, output, target):
        """
        Parse Nuclei JSON output.
        
        Args:
            output (str): Nuclei stdout (JSON lines)
            target (str): Target URL
        
        Returns:
            list: List of finding dictionaries
        """
        findings = []
        
        for line in output.split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                finding = {
                    'target': target,
                    'name': data.get('info', {}).get('name', 'Unknown'),
                    'severity': data.get('info', {}).get('severity', 'unknown'),
                    'description': data.get('info', {}).get('description', ''),
                    'template_id': data.get('template-id', ''),
                    'matched_at': data.get('matched-at', target),
                    'evidence': {
                        'type': data.get('type', ''),
                        'matcher_name': data.get('matcher-name', ''),
                        'extracted_results': data.get('extracted-results', [])
                    },
                    'scanner': 'nuclei'
                }
                
                findings.append(finding)
                
            except json.JSONDecodeError:
                log_warning(f"Failed to parse Nuclei output line: {line[:100]}")
                continue
        
        return findings
    
    def get_available_templates(self):
        """
        Get list of available Nuclei templates.
        
        Returns:
            list: List of template paths
        """
        try:
            result = subprocess.run(
                ['nuclei', '-tl'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                templates = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                return templates
            
        except Exception as e:
            log_warning(f"Failed to list Nuclei templates: {e}")
        
        return []
