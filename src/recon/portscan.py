"""Conservative port scanning with nmap."""

import subprocess
import json

from utils.logger import log_info, log_warning, log_error
from utils.sanitizer import sanitize_domain


class PortScanner:
    """Conservative port scanner using nmap."""
    
    def __init__(self, config):
        """
        Initialize port scanner.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        # Conservative port list (common web/API ports)
        self.default_ports = '80,443,8080,8443,3000,5000,8000,8888'
    
    def scan(self, target, ports=None):
        """
        Scan target for open ports.
        
        Args:
            target (str): Target IP or domain
            ports (str): Port specification (default: common web ports)
        
        Returns:
            dict: Scan results
        """
        target = sanitize_domain(target)
        if not target:
            log_error(f"Invalid target: {target}")
            return {'open_ports': []}
        
        if ports is None:
            ports = self.default_ports
        
        log_info(f"Scanning {target} for open ports: {ports}")
        
        try:
            # Conservative nmap scan: -T3 timing, --open only, no aggressive scripts
            result = subprocess.run(
                [
                    'nmap',
                    '-p', ports,
                    '-T3',  # Normal timing (not aggressive)
                    '--open',  # Only show open ports
                    '-Pn',  # Skip ping (assume host is up)
                    '--max-retries', '2',
                    '--host-timeout', f"{self.config['TIMEOUT']}s",
                    target
                ],
                capture_output=True,
                text=True,
                timeout=self.config['TIMEOUT'] * 2
            )
            
            if result.returncode == 0:
                open_ports = self._parse_nmap_output(result.stdout)
                log_info(f"Found {len(open_ports)} open ports on {target}")
                return {
                    'target': target,
                    'open_ports': open_ports
                }
            else:
                log_warning(f"nmap scan failed for {target}")
                return {'target': target, 'open_ports': []}
                
        except FileNotFoundError:
            log_warning("nmap not found, skipping port scan")
            return {'target': target, 'open_ports': []}
        except subprocess.TimeoutExpired:
            log_warning(f"nmap scan timed out for {target}")
            return {'target': target, 'open_ports': []}
        except Exception as e:
            log_error(f"Port scan failed: {e}")
            return {'target': target, 'open_ports': []}
    
    def _parse_nmap_output(self, output):
        """
        Parse nmap output to extract open ports.
        
        Args:
            output (str): nmap stdout
        
        Returns:
            list: List of open port dictionaries
        """
        open_ports = []
        
        for line in output.split('\n'):
            # Look for lines like: "80/tcp   open  http"
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    port = port_proto.split('/')[0]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    
                    open_ports.append({
                        'port': int(port),
                        'protocol': 'tcp',
                        'service': service
                    })
        
        return open_ports
