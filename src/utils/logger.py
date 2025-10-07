"""Structured logging utilities."""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path


# Global logger instance
_logger = None


def setup_logger(config):
    """
    Setup structured logger with configuration.
    
    Args:
        config (dict): Configuration dictionary
    """
    global _logger
    
    log_level = getattr(logging, config.get('LOG_LEVEL', 'INFO'))
    log_format = config.get('LOG_FORMAT', 'json')
    
    # Create logs directory
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    # Create logger
    _logger = logging.getLogger('kali_bounty_scanner')
    _logger.setLevel(log_level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    if log_format == 'json':
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
    
    _logger.addHandler(console_handler)
    
    # File handler (always JSON for parsing)
    log_file = log_dir / f"scanner_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(JSONFormatter())
    _logger.addHandler(file_handler)


class JSONFormatter(logging.Formatter):
    """Format log records as JSON."""
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


def get_logger():
    """Get the global logger instance."""
    global _logger
    if _logger is None:
        # Fallback logger if setup_logger not called
        logging.basicConfig(level=logging.INFO)
        _logger = logging.getLogger('kali_bounty_scanner')
    return _logger


def log_info(message):
    """Log info message."""
    get_logger().info(message)
    print(f"[INFO] {message}")


def log_warning(message):
    """Log warning message."""
    get_logger().warning(message)
    print(f"[WARN] {message}")


def log_error(message):
    """Log error message."""
    get_logger().error(message)
    print(f"[ERROR] {message}")


def log_debug(message):
    """Log debug message."""
    get_logger().debug(message)
