"""Nikto scanner wrapper with safe flags."""

import subprocess
import json
from pathlib import Path

from utils.logger import log_info, log_warning, log_error
from utils.sanitizer import sanitize_url


class NiktoRunner:
    """Nikto web server scanner with conservative settings."""
    
    def __init__(self, config):
        """
        Initialize Nikto runner.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
    
    def run(self, target):
        """
        Run Nikto scan on target.
        
        Args:
            target (str): Target URL
        
        Returns:
            list: List of findings
        """
        target = sanitize_url(target)
        if not target:
            log_error(f"Invalid target URL: {target}")
            return []
        
        log_info(f"Running Nikto scan on {target}")
        
        try:
            # Create temp output file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
                output_file = f.name
            
            # Run nikto with safe flags
            cmd = [
                'nikto',
                '-h', target,
                '-Format', 'json',
                '-output', output_file,
                '-Tuning', '1,2,3',  # Interesting files, misconfig, info disclosure
                '-timeout', str(self.config['TIMEOUT']),
                '-maxtime', '300',  # 5 minute max
                '-nointeractive'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=360
            )
            
            # Parse output
            findings = self._parse_nikto_output(output_file, target)
            
            # Cleanup
            Path(output_file).unlink(missing_ok=True)
            
            log_info(f"Nikto found {len(findings)} potential issues")
            return findings
            
        except FileNotFoundError:
            log_warning("nikto not found, skipping scan")
            return []
        except subprocess.TimeoutExpired:
            log_warning(f"Nikto scan timed out for {target}")
            return []
        except Exception as e:
            log_error(f"Nikto scan failed: {e}")
            return []
    
    def _parse_nikto_output(self, output_file, target):
        """
        Parse Nikto JSON output.
        
        Args:
            output_file (str): Path to output file
            target (str): Target URL
        
        Returns:
            list: List of finding dictionaries
        """
        findings = []
        
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            # Nikto JSON structure varies, handle gracefully
            vulnerabilities = data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                finding = {
                    'target': target,
                    'name': vuln.get('msg', 'Unknown'),
                    'severity': 'low',  # Nikto doesn't provide severity
                    'description': vuln.get('msg', ''),
                    'evidence': {
                        'url': vuln.get('url', ''),
                        'method': vuln.get('method', ''),
                        'osvdb': vuln.get('OSVDB', '')
                    },
                    'scanner': 'nikto'
                }
                findings.append(finding)
        
        except Exception as e:
            log_warning(f"Failed to parse Nikto output: {e}")
        
        return findings
