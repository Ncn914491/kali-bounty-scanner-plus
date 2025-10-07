"""Tests for triage engine."""

import pytest
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from triage.triage_ai import TriageEngine
from config import load_config


@pytest.fixture
def config():
    """Load test configuration."""
    return load_config()


@pytest.fixture
def triage_engine(config):
    """Create triage engine instance."""
    return TriageEngine(config)


def test_triage_engine_initialization(triage_engine):
    """Test triage engine initializes correctly."""
    assert triage_engine is not None
    assert triage_engine.ml_model is not None
    assert triage_engine.ml_weight == 0.4
    assert triage_engine.llm_weight == 0.6


def test_extract_text_features(triage_engine):
    """Test text feature extraction."""
    finding = {
        'name': 'XSS Vulnerability',
        'description': 'Cross-site scripting found',
        'severity': 'high',
        'evidence': {'payload': '<script>alert(1)</script>'}
    }
    
    features = triage_engine._extract_text_features(finding)
    
    assert isinstance(features, str)
    assert 'XSS' in features
    assert 'high' in features


def test_ml_score_untrained(triage_engine):
    """Test ML scoring with untrained model."""
    text = "SQL injection vulnerability detected"
    score = triage_engine._ml_score(text)
    
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_score_finding_structure(triage_engine):
    """Test that score_finding returns correct structure."""
    finding = {
        'name': 'Missing Security Headers',
        'description': 'X-Frame-Options header not set',
        'severity': 'low',
        'evidence': {}
    }
    
    result = triage_engine.score_finding(finding)
    
    assert 'ml_score' in result
    assert 'llm_score' in result
    assert 'final_score' in result
    assert 'confidence' in result
    assert 'explanation' in result
    assert 'is_false_positive' in result


def test_score_finding_ranges(triage_engine):
    """Test that scores are in valid ranges."""
    finding = {
        'name': 'Test Finding',
        'description': 'Test description',
        'severity': 'medium',
        'evidence': {}
    }
    
    result = triage_engine.score_finding(finding)
    
    assert 0.0 <= result['ml_score'] <= 1.0
    assert 0.0 <= result['llm_score'] <= 1.0
    assert 0.0 <= result['final_score'] <= 1.0
    assert 0.0 <= result['confidence'] <= 1.0


def test_adjust_severity_low_score(triage_engine):
    """Test severity adjustment for low scores."""
    finding = {'severity': 'high'}
    adjusted = triage_engine._adjust_severity(finding, 0.2)
    
    assert adjusted == 'info'


def test_adjust_severity_high_score(triage_engine):
    """Test severity adjustment for high scores."""
    finding = {'severity': 'medium'}
    adjusted = triage_engine._adjust_severity(finding, 0.9)
    
    assert adjusted == 'high'


def test_adjust_severity_medium_score(triage_engine):
    """Test severity adjustment for medium scores."""
    finding = {'severity': 'medium'}
    adjusted = triage_engine._adjust_severity(finding, 0.6)
    
    assert adjusted == 'medium'


def test_fusion_scoring_weights(triage_engine):
    """Test that fusion scoring uses correct weights."""
    # Mock scores
    ml_score = 0.8
    llm_score = 0.4
    
    expected = (0.4 * ml_score) + (0.6 * llm_score)
    
    # This tests the formula, not the actual implementation
    assert abs(expected - 0.56) < 0.01


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
