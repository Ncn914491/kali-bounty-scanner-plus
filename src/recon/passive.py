"""Passive reconnaissance using subfinder, amass, and httpx."""

import subprocess
import json
from pathlib import Path

from utils.logger import log_info, log_warning, log_error
from utils.sanitizer import sanitize_domain
from utils.rate_limiter import RateLimiter


class PassiveRecon:
    """Passive reconnaissance coordinator."""
    
    def __init__(self, config):
        """
        Initialize passive recon.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self.rate_limiter = RateLimiter(
            rate_per_minute=config['SCAN_RATE'],
            max_concurrency=config['MAX_CONCURRENCY']
        )
    
    def run(self, target):
        """
        Run passive reconnaissance on target.
        
        Args:
            target (str): Target domain
        
        Returns:
            dict: Recon results with subdomains and live hosts
        """
        target = sanitize_domain(target)
        if not target:
            log_error(f"Invalid target domain: {target}")
            return {'subdomains': [], 'live_hosts': []}
        
        log_info(f"Starting passive recon for {target}")
        
        results = {
            'target': target,
            'subdomains': [],
            'live_hosts': []
        }
        
        # Subdomain enumeration
        subdomains = self._enumerate_subdomains(target)
        results['subdomains'] = subdomains
        
        # HTTP probing
        if subdomains:
            live_hosts = self._probe_http(subdomains)
            results['live_hosts'] = live_hosts
        
        return results
    
    def _enumerate_subdomains(self, target):
        """
        Enumerate subdomains using subfinder.
        
        Args:
            target (str): Target domain
        
        Returns:
            list: List of discovered subdomains
        """
        log_info(f"Enumerating subdomains for {target}")
        
        subdomains = set()
        
        # Try subfinder
        try:
            result = subprocess.run(
                ['subfinder', '-d', target, '-silent', '-all'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                found = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                subdomains.update(found)
                log_info(f"Subfinder found {len(found)} subdomains")
        except FileNotFoundError:
            log_warning("subfinder not found, skipping")
        except subprocess.TimeoutExpired:
            log_warning("subfinder timed out")
        except Exception as e:
            log_warning(f"subfinder failed: {e}")
        
        # Add target itself
        subdomains.add(target)
        
        return sorted(list(subdomains))
    
    def _probe_http(self, subdomains):
        """
        Probe subdomains for HTTP services using httpx.
        
        Args:
            subdomains (list): List of subdomains
        
        Returns:
            list: List of live HTTP(S) hosts
        """
        log_info(f"Probing {len(subdomains)} subdomains for HTTP services")
        
        live_hosts = []
        
        try:
            # Create temp file with subdomains
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write('\n'.join(subdomains))
                temp_file = f.name
            
            # Run httpx
            result = subprocess.run(
                [
                    'httpx',
                    '-l', temp_file,
                    '-silent',
                    '-threads', str(self.config['HTTPX_THREADS']),
                    '-timeout', str(self.config['TIMEOUT']),
                    '-no-color',
                    '-status-code',
                    '-title'
                ],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        # Extract URL (first field)
                        url = line.split()[0] if line.split() else None
                        if url:
                            live_hosts.append(url)
                
                log_info(f"Found {len(live_hosts)} live HTTP services")
            
            # Cleanup
            Path(temp_file).unlink(missing_ok=True)
            
        except FileNotFoundError:
            log_warning("httpx not found, skipping HTTP probing")
        except subprocess.TimeoutExpired:
            log_warning("httpx timed out")
        except Exception as e:
            log_warning(f"httpx failed: {e}")
        
        return live_hosts
