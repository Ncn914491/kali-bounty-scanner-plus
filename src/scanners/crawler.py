"""Web crawler with conservative settings."""

import time
from urllib.parse import urljoin, urlparse

from utils.logger import log_info, log_warning, log_error
from utils.sanitizer import sanitize_url


class Crawler:
    """Conservative web crawler with depth and rate limits."""
    
    def __init__(self, config):
        """
        Initialize crawler.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self.delay = config['CRAWLER_DELAY']
        self.max_depth = config['CRAWLER_MAX_DEPTH']
        self.visited = set()
    
    def crawl(self, start_url, max_pages=50):
        """
        Crawl website starting from URL.
        
        Args:
            start_url (str): Starting URL
            max_pages (int): Maximum pages to crawl
        
        Returns:
            list: List of discovered URLs
        """
        start_url = sanitize_url(start_url)
        if not start_url:
            log_error(f"Invalid start URL: {start_url}")
            return []
        
        log_info(f"Crawling {start_url} (max_depth={self.max_depth}, max_pages={max_pages})")
        
        # For now, use simple requests-based crawling
        # In production, consider using playwright for JS-heavy sites
        discovered = []
        to_visit = [(start_url, 0)]  # (url, depth)
        
        base_domain = urlparse(start_url).netloc
        
        while to_visit and len(discovered) < max_pages:
            url, depth = to_visit.pop(0)
            
            if url in self.visited or depth > self.max_depth:
                continue
            
            self.visited.add(url)
            discovered.append(url)
            
            # Rate limiting delay
            time.sleep(self.delay)
            
            # Fetch and parse (simplified - in production use proper HTML parser)
            try:
                import requests
                response = requests.get(
                    url,
                    timeout=self.config['TIMEOUT'],
                    headers={'User-Agent': 'Mozilla/5.0 (Security Research Bot)'}
                )
                
                if response.status_code == 200:
                    # Simple link extraction (in production, use BeautifulSoup)
                    links = self._extract_links(response.text, url, base_domain)
                    
                    # Add new links to queue
                    for link in links:
                        if link not in self.visited:
                            to_visit.append((link, depth + 1))
                
            except Exception as e:
                log_warning(f"Failed to crawl {url}: {e}")
                continue
        
        log_info(f"Crawled {len(discovered)} pages")
        return discovered
    
    def _extract_links(self, html, base_url, base_domain):
        """
        Extract links from HTML.
        
        Args:
            html (str): HTML content
            base_url (str): Base URL for relative links
            base_domain (str): Base domain to stay within
        
        Returns:
            list: List of absolute URLs
        """
        links = []
        
        # Simple regex-based extraction (in production, use proper parser)
        import re
        href_pattern = r'href=["\']([^"\']+)["\']'
        
        for match in re.finditer(href_pattern, html):
            href = match.group(1)
            
            # Skip anchors, javascript, etc.
            if href.startswith('#') or href.startswith('javascript:'):
                continue
            
            # Make absolute
            absolute_url = urljoin(base_url, href)
            
            # Only include same domain
            if urlparse(absolute_url).netloc == base_domain:
                links.append(absolute_url)
        
        return links[:20]  # Limit links per page
