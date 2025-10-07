"""Tests for input sanitization."""

import pytest
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from utils.sanitizer import (
    sanitize_filename,
    sanitize_domain,
    sanitize_url,
    is_safe_path
)


def test_sanitize_filename_basic():
    """Test basic filename sanitization."""
    assert sanitize_filename('test.txt') == 'test.txt'
    assert sanitize_filename('my-file_123.json') == 'my-file_123.json'


def test_sanitize_filename_path_traversal():
    """Test that path traversal is prevented."""
    assert '/' not in sanitize_filename('../../../etc/passwd')
    assert '\\' not in sanitize_filename('..\\..\\windows\\system32')


def test_sanitize_filename_special_chars():
    """Test that special characters are removed."""
    result = sanitize_filename('file<>:"|?*.txt')
    assert '<' not in result
    assert '>' not in result
    assert ':' not in result


def test_sanitize_filename_length():
    """Test that long filenames are truncated."""
    long_name = 'a' * 300 + '.txt'
    result = sanitize_filename(long_name)
    assert len(result) <= 200


def test_sanitize_domain_valid():
    """Test valid domain sanitization."""
    assert sanitize_domain('example.com') == 'example.com'
    assert sanitize_domain('sub.example.com') == 'sub.example.com'
    assert sanitize_domain('api-v2.example.com') == 'api-v2.example.com'


def test_sanitize_domain_with_protocol():
    """Test domain extraction from URL."""
    assert sanitize_domain('https://example.com') == 'example.com'
    assert sanitize_domain('http://api.example.com') == 'api.example.com'


def test_sanitize_domain_with_port():
    """Test domain extraction with port."""
    assert sanitize_domain('example.com:8080') == 'example.com'
    assert sanitize_domain('https://example.com:443') == 'example.com'


def test_sanitize_domain_invalid():
    """Test that invalid domains return None."""
    assert sanitize_domain('not a domain!') is None
    assert sanitize_domain('') is None
    assert sanitize_domain('..') is None


def test_sanitize_domain_ip():
    """Test IP address sanitization."""
    assert sanitize_domain('192.168.1.1') == '192.168.1.1'
    assert sanitize_domain('10.0.0.1') == '10.0.0.1'


def test_sanitize_url_valid():
    """Test valid URL sanitization."""
    assert sanitize_url('https://example.com') == 'https://example.com'
    assert sanitize_url('http://api.example.com/path') == 'http://api.example.com/path'


def test_sanitize_url_invalid_scheme():
    """Test that non-HTTP schemes are rejected."""
    assert sanitize_url('ftp://example.com') is None
    assert sanitize_url('file:///etc/passwd') is None
    assert sanitize_url('javascript:alert(1)') is None


def test_sanitize_url_no_scheme():
    """Test that URLs without scheme are rejected."""
    assert sanitize_url('example.com') is None
    assert sanitize_url('//example.com') is None


def test_is_safe_path_safe():
    """Test that safe paths are allowed."""
    assert is_safe_path('file.txt', '.')
    assert is_safe_path('subdir/file.txt', '.')
    assert is_safe_path('./file.txt', '.')


def test_is_safe_path_traversal():
    """Test that path traversal is blocked."""
    assert not is_safe_path('../file.txt', '.')
    assert not is_safe_path('../../etc/passwd', '.')
    assert not is_safe_path('/etc/passwd', '.')


def test_is_safe_path_absolute():
    """Test that absolute paths outside base are blocked."""
    assert not is_safe_path('/tmp/file.txt', '.')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
