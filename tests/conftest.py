"""
Pytest configuration and common fixtures for Quantum Secret Vault tests.
"""

import pytest
import os
import tempfile
import shutil
from pathlib import Path

# Add src to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.fixture
def sample_secret():
    """Sample secret text for testing."""
    return "abandon ability able about above absent absorb abstract absurd abuse access accident"

@pytest.fixture
def sample_password():
    """Sample password for testing."""
    return "my_test_password_123"
