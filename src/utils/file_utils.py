"""
File utility functions for the quantum secret vault.
"""

import os
import json
import tempfile
from typing import Any, Dict

def ensure_directory(path: str) -> None:
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        path: Directory path to ensure exists
    """
    os.makedirs(path, exist_ok=True)

def safe_write_json(data: Dict[str, Any], filepath: str, indent: int = 2) -> None:
    """
    Safely write JSON data to a file using atomic write.
    
    Args:
        data: Data to write
        filepath: Target file path
        indent: JSON indentation
    """
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    # Write to temporary file first
    with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=os.path.dirname(filepath)) as temp_file:
        json.dump(data, temp_file, indent=indent)
        temp_path = temp_file.name
    
    # Atomic move to final location
    os.replace(temp_path, filepath)

def safe_read_json(filepath: str) -> Dict[str, Any]:
    """
    Safely read JSON data from a file.
    
    Args:
        filepath: File path to read from
        
    Returns:
        Parsed JSON data
        
    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file contains invalid JSON
    """
    with open(filepath, 'r') as f:
        return json.load(f)

def get_file_size(filepath: str) -> int:
    """
    Get file size in bytes.
    
    Args:
        filepath: File path
        
    Returns:
        File size in bytes
    """
    return os.path.getsize(filepath) 