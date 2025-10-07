"""Rate limiting utilities."""

import time
import threading
from collections import deque


class RateLimiter:
    """Token bucket rate limiter."""
    
    def __init__(self, rate_per_minute, max_concurrency):
        """
        Initialize rate limiter.
        
        Args:
            rate_per_minute (int): Maximum requests per minute
            max_concurrency (int): Maximum concurrent operations
        """
        self.rate = rate_per_minute
        self.interval = 60.0 / rate_per_minute  # seconds between requests
        self.max_concurrency = max_concurrency
        
        self.last_request = 0
        self.lock = threading.Lock()
        self.semaphore = threading.Semaphore(max_concurrency)
        
        # Track request times for rate calculation
        self.request_times = deque(maxlen=rate_per_minute)
    
    def acquire(self):
        """
        Acquire permission to make a request.
        Blocks until rate limit allows.
        """
        # Acquire concurrency semaphore
        self.semaphore.acquire()
        
        with self.lock:
            now = time.time()
            
            # Calculate time since last request
            time_since_last = now - self.last_request
            
            # If we need to wait, sleep
            if time_since_last < self.interval:
                sleep_time = self.interval - time_since_last
                time.sleep(sleep_time)
                now = time.time()
            
            self.last_request = now
            self.request_times.append(now)
    
    def release(self):
        """Release concurrency semaphore."""
        self.semaphore.release()
    
    def get_current_rate(self):
        """
        Get current request rate.
        
        Returns:
            float: Requests per minute
        """
        if len(self.request_times) < 2:
            return 0.0
        
        now = time.time()
        # Count requests in last minute
        recent = [t for t in self.request_times if now - t < 60]
        return len(recent)
    
    def __enter__(self):
        """Context manager entry."""
        self.acquire()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.release()
