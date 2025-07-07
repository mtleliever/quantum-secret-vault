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
def sample_seed():
    """Sample BIP-39 seed phrase for testing."""
    return "abandon ability able about above absent absorb abstract absurd abuse access accident"

@pytest.fixture
def sample_passphrase():
    """Sample passphrase for testing."""
    return "my_test_passphrase_123"

@pytest.fixture
def sample_images():
    """Create sample image files for steganography tests."""
    temp_dir = tempfile.mkdtemp()
    images = []
    
    # Create simple text files as "images" for testing
    for i in range(7):
        img_path = os.path.join(temp_dir, f"test_image_{i}.txt")
        with open(img_path, 'w') as f:
            f.write(f"This is test image {i} for steganography testing.")
        images.append(img_path)
    
    yield images
    shutil.rmtree(temp_dir, ignore_errors=True) 