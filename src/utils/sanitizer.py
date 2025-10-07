"""Input sanitization utilities."""

import re
from pathlib import Path
from urllib.parse import urlparse


def sanitize_filename(filename):
    """
    Sanitize a filename to prevent path traversal and invalid characters.
    
    Args:
        filename (str): Input filename
    
    Returns:
        str: Sanitized filename
    """
    # Remove path separators
    filename = filename.replace('/', '_').replace('\\', '_')
    
    # Remove dangerous characters
    filename = re.sub(r'[^\w\-\.]', '_', filename)
    
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    
    return filename


def sanitize_domain(domain):
    """
    Validate and sanitize a domain name.
    
    Args:
        domain (str): Input domain
    
    Returns:
        str: Sanitized domain or None if invalid
    """
    # Remove protocol if present
    if '://' in domain:
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path
    
    # Remove port
    domain = domain.split(':')[0]
    
    # Validate domain format
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    if re.match(domain_pattern, domain):
        return domain.lower()
    
    # Check if it's an IP address
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if re.match(ip_pattern, domain):
        return domain
    
    return None


def sanitize_url(url):
    """
    Validate and sanitize a URL.
    
    Args:
        url (str): Input URL
    
    Returns:
        str: Sanitized URL or None if invalid
    """
    try:
        parsed = urlparse(url)
        
        # Must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            return None
        
        # Only allow http/https
        if parsed.scheme not in ['http', 'https']:
            return None
        
        return url
    except Exception:
        return None


def is_safe_path(path, base_dir='.'):
    """
    Check if a path is safe (no traversal outside base_dir).
    
    Args:
        path (str): Path to check
        base_dir (str): Base directory
    
    Returns:
        bool: True if safe
    """
    try:
        base = Path(base_dir).resolve()
        target = (base / path).resolve()
        return target.is_relative_to(base)
    except Exception:
        return False
