#!/usr/bin/env python3
"""
Test runner for Quantum Secret Vault using pytest.
"""

import sys
import subprocess
from pathlib import Path

def run_pytest_tests():
    """Run tests using pytest."""
    print("🚀 Running Quantum Secret Vault tests with pytest...\n")
    
    # Run pytest on the tests directory
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        "tests/", 
        "-v", 
        "--tb=short"
    ], capture_output=False)
    
    return result.returncode == 0

if __name__ == "__main__":
    success = run_pytest_tests()
    sys.exit(0 if success else 1) 