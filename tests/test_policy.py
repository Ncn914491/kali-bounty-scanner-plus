"""Tests for policy engine."""

import pytest
import json
import tempfile
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from policy.policy_engine import PolicyEngine
from config import load_config


@pytest.fixture
def config():
    """Load test configuration."""
    return load_config()


@pytest.fixture
def policy_engine(config):
    """Create policy engine instance."""
    return PolicyEngine(config)


@pytest.fixture
def sample_scope_file():
    """Create a temporary scope file for testing."""
    scope_data = {
        "in_scope": [
            "example.com",
            "*.example.com",
            "api.example.io"
        ],
        "out_of_scope": [
            "test.example.com",
            "dev.example.com"
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(scope_data, f)
        temp_file = f.name
    
    yield temp_file
    
    # Cleanup
    Path(temp_file).unlink(missing_ok=True)


def test_policy_engine_initialization(policy_engine):
    """Test policy engine initializes correctly."""
    assert policy_engine is not None
    assert policy_engine.blocked_manifest is not None
    assert 'blocked_patterns' in policy_engine.blocked_manifest


def test_blocked_patterns_loaded(policy_engine):
    """Test that blocked patterns are loaded."""
    patterns = policy_engine.blocked_manifest.get('blocked_patterns', [])
    assert len(patterns) > 0
    
    # Check for expected patterns
    pattern_ids = [p['id'] for p in patterns]
    assert 'rce-templates' in pattern_ids
    assert 'sql-exploit' in pattern_ids
    assert 'dos-attacks' in pattern_ids


def test_scope_validation_in_scope(policy_engine, sample_scope_file):
    """Test that in-scope targets are allowed."""
    result = policy_engine.is_target_in_scope('example.com', sample_scope_file)
    
    assert result['decision'] == 'ALLOWED'
    assert result['confidence'] == 1.0


def test_scope_validation_subdomain(policy_engine, sample_scope_file):
    """Test that wildcard subdomains work."""
    result = policy_engine.is_target_in_scope('app.example.com', sample_scope_file)
    
    assert result['decision'] == 'ALLOWED'


def test_scope_validation_out_of_scope(policy_engine, sample_scope_file):
    """Test that out-of-scope targets are blocked."""
    result = policy_engine.is_target_in_scope('test.example.com', sample_scope_file)
    
    assert result['decision'] == 'BLOCKED'
    assert result['confidence'] == 1.0


def test_scope_validation_no_match(policy_engine, sample_scope_file):
    """Test that unmatched targets return UNKNOWN."""
    result = policy_engine.is_target_in_scope('other.com', sample_scope_file)
    
    # Without Gemini, should return UNKNOWN
    assert result['decision'] in ['UNKNOWN', 'BLOCKED']


def test_scope_validation_no_file(policy_engine):
    """Test behavior when no scope file provided."""
    result = policy_engine.is_target_in_scope('example.com', None)
    
    assert result['decision'] == 'UNKNOWN'
    assert 'No scope file provided' in result['reason']


def test_scanner_action_blocked(policy_engine):
    """Test that blocked scanner actions are caught."""
    action = {
        'scanner': 'nuclei',
        'target': 'example.com',
        'template': 'rce-exploit-template'
    }
    
    result = policy_engine.validate_scanner_action(action)
    
    assert result['decision'] == 'BLOCKED'
    assert result['confidence'] == 1.0


def test_scanner_action_allowed(policy_engine):
    """Test that safe scanner actions are allowed."""
    action = {
        'scanner': 'nuclei',
        'target': 'example.com',
        'template': 'http-missing-security-headers',
        'severity': 'low'
    }
    
    result = policy_engine.validate_scanner_action(action)
    
    assert result['decision'] in ['ALLOWED', 'REQUIRES_VALIDATION']


def test_scanner_action_requires_validation(policy_engine):
    """Test that moderate-risk actions require validation."""
    action = {
        'scanner': 'nuclei',
        'target': 'example.com',
        'template': 'auth-bypass-test'
    }
    
    result = policy_engine.validate_scanner_action(action)
    
    # Without Gemini, should require validation or be blocked
    assert result['decision'] in ['REQUIRES_VALIDATION', 'BLOCKED']


def test_pattern_matching_exact(policy_engine):
    """Test exact domain matching."""
    assert policy_engine._matches_pattern('example.com', 'example.com')
    assert not policy_engine._matches_pattern('app.example.com', 'example.com')


def test_pattern_matching_wildcard(policy_engine):
    """Test wildcard domain matching."""
    assert policy_engine._matches_pattern('app.example.com', '*.example.com')
    assert policy_engine._matches_pattern('api.example.com', '*.example.com')
    assert not policy_engine._matches_pattern('example.com', '*.example.com')


def test_pattern_matching_subdomain(policy_engine):
    """Test subdomain matching."""
    assert policy_engine._matches_pattern('app.example.com', 'example.com')
    assert policy_engine._matches_pattern('api.app.example.com', 'example.com')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
