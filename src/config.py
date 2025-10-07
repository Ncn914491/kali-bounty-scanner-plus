"""Configuration loader with sane defaults."""

import os
from pathlib import Path
from dotenv import load_dotenv


def load_config():
    """
    Load configuration from .env file with conservative defaults.
    
    Returns:
        dict: Configuration dictionary with all settings
    """
    # Load .env file
    env_path = Path(__file__).parent.parent / '.env'
    load_dotenv(env_path)
    
    config = {
        # API Keys
        'GEMINI_API_KEY': os.getenv('GEMINI_API_KEY', ''),
        
        # Rate Limits (conservative defaults)
        'SCAN_RATE': int(os.getenv('SCAN_RATE', '5')),  # requests per minute
        'MAX_CONCURRENCY': int(os.getenv('MAX_CONCURRENCY', '4')),
        'TIMEOUT': int(os.getenv('TIMEOUT', '20')),  # seconds
        
        # Policy Controls
        'ALLOW_MANUAL_UNBLOCK': os.getenv('ALLOW_MANUAL_UNBLOCK', 'false').lower() == 'true',
        'STORE_LLM_RESPONSES': os.getenv('STORE_LLM_RESPONSES', 'true').lower() == 'true',
        
        # Logging
        'LOG_LEVEL': os.getenv('LOG_LEVEL', 'INFO'),
        'LOG_FORMAT': os.getenv('LOG_FORMAT', 'json'),
        
        # Output
        'OUTPUT_DIR': os.getenv('OUTPUT_DIR', './outputs'),
        
        # Triage Model Weights
        'ML_WEIGHT': float(os.getenv('ML_WEIGHT', '0.4')),
        'LLM_WEIGHT': float(os.getenv('LLM_WEIGHT', '0.6')),
        
        # Scanner Specific
        'NUCLEI_RATE_LIMIT': int(os.getenv('NUCLEI_RATE_LIMIT', '5')),
        'NUCLEI_CONCURRENCY': int(os.getenv('NUCLEI_CONCURRENCY', '3')),
        'HTTPX_THREADS': int(os.getenv('HTTPX_THREADS', '10')),
        'CRAWLER_DELAY': float(os.getenv('CRAWLER_DELAY', '0.5')),
        'CRAWLER_MAX_DEPTH': int(os.getenv('CRAWLER_MAX_DEPTH', '3')),
        
        # Database
        'DB_PATH': os.getenv('DB_PATH', './db/scanner.db'),
    }
    
    # Validate critical settings
    if config['SCAN_RATE'] > 100:
        raise ValueError("SCAN_RATE too high (max 100 req/min for safety)")
    
    if config['MAX_CONCURRENCY'] > 20:
        raise ValueError("MAX_CONCURRENCY too high (max 20 for safety)")
    
    return config


def get_config_value(key, default=None):
    """Get a single config value."""
    config = load_config()
    return config.get(key, default)
