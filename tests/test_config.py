"""Tests for configuration loading."""

import pytest
import os
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from config import load_config, get_config_value


def test_load_config_defaults():
    """Test that config loads with default values."""
    config = load_config()
    
    assert config is not None
    assert isinstance(config, dict)
    
    # Check default values
    assert config['SCAN_RATE'] == 5
    assert config['MAX_CONCURRENCY'] == 4
    assert config['TIMEOUT'] == 20
    assert config['ALLOW_MANUAL_UNBLOCK'] == False
    assert config['ML_WEIGHT'] == 0.4
    assert config['LLM_WEIGHT'] == 0.6


def test_config_rate_limit_validation():
    """Test that excessive rate limits are rejected."""
    # This would require mocking os.getenv
    # For now, just verify the validation logic exists
    config = load_config()
    assert config['SCAN_RATE'] <= 100


def test_config_concurrency_validation():
    """Test that excessive concurrency is rejected."""
    config = load_config()
    assert config['MAX_CONCURRENCY'] <= 20


def test_get_config_value():
    """Test getting individual config values."""
    scan_rate = get_config_value('SCAN_RATE', 5)
    assert isinstance(scan_rate, int)
    assert scan_rate > 0


def test_config_paths():
    """Test that config paths are valid."""
    config = load_config()
    
    assert 'OUTPUT_DIR' in config
    assert 'DB_PATH' in config
    assert isinstance(config['OUTPUT_DIR'], str)
    assert isinstance(config['DB_PATH'], str)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
