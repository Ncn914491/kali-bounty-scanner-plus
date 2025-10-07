"""FFUF fuzzer wrapper with conservative settings."""

import subprocess
import json
import tempfile
from pathlib import Path

from utils.logger import log_info, log_warning, log_error
from utils.sanitizer import sanitize_url


class FFUFRunner:
    """FFUF fuzzer with rate limiting and short wordlists."""
    
    def __init__(self, config):
        """
        Initialize FFUF runner.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self.default_wordlist = self._get_default_wordlist()
    
    def _get_default_wordlist(self):
        """Get path to default wordlist."""
        # Common wordlist locations
        candidates = [
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            'wordlists/common.txt'
        ]
        
        for path in candidates:
            if Path(path).exists():
                return path
        
        return None
    
    def fuzz_directories(self, target, wordlist=None, max_time=300):
        """
        Fuzz directories on target.
        
        Args:
            target (str): Target URL (with FUZZ placeholder or will append)
            wordlist (str): Path to wordlist
            max_time (int): Maximum scan time in seconds
        
        Returns:
            list: List of discovered paths
        """
        target = sanitize_url(target)
        if not target:
            log_error(f"Invalid target URL: {target}")
            return []
        
        if wordlist is None:
            wordlist = self.default_wordlist
        
        if not wordlist or not Path(wordlist).exists():
            log_warning("No wordlist available for fuzzing")
            return []
        
        # Ensure target has FUZZ placeholder
        if 'FUZZ' not in target:
            target = target.rstrip('/') + '/FUZZ'
        
        log_info(f"Fuzzing directories on {target}")
        
        try:
            # Create temp output file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
                output_file = f.name
            
            # Run ffuf with conservative settings
            cmd = [
                'ffuf',
                '-u', target,
                '-w', wordlist,
                '-o', output_file,
                '-of', 'json',
                '-rate', str(self.config['SCAN_RATE']),
                '-timeout', str(self.config['TIMEOUT']),
                '-maxtime', str(max_time),
                '-mc', '200,204,301,302,307,401,403',  # Match these status codes
                '-fc', '404',  # Filter 404s
                '-t', str(self.config['MAX_CONCURRENCY']),
                '-silent'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max_time + 30
            )
            
            # Parse output
            findings = self._parse_ffuf_output(output_file, target)
            
            # Cleanup
            Path(output_file).unlink(missing_ok=True)
            
            log_info(f"FFUF found {len(findings)} paths")
            return findings
            
        except FileNotFoundError:
            log_warning("ffuf not found, skipping fuzzing")
            return []
        except subprocess.TimeoutExpired:
            log_warning(f"FFUF timed out for {target}")
            return []
        except Exception as e:
            log_error(f"FFUF failed: {e}")
            return []
    
    def _parse_ffuf_output(self, output_file, target):
        """
        Parse FFUF JSON output.
        
        Args:
            output_file (str): Path to output file
            target (str): Target URL
        
        Returns:
            list: List of discovered paths
        """
        findings = []
        
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            results = data.get('results', [])
            
            for result in results:
                finding = {
                    'target': target,
                    'name': f"Discovered path: {result.get('input', {}).get('FUZZ', '')}",
                    'severity': 'info',
                    'description': f"Found accessible path via fuzzing",
                    'evidence': {
                        'url': result.get('url', ''),
                        'status': result.get('status', 0),
                        'length': result.get('length', 0),
                        'words': result.get('words', 0)
                    },
                    'scanner': 'ffuf'
                }
                findings.append(finding)
        
        except Exception as e:
            log_warning(f"Failed to parse FFUF output: {e}")
        
        return findings
