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
    Safely write JSON data to a file using atomic write with secure permissions.
    
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
    
    # Set secure permissions (owner read/write only)
    os.chmod(temp_path, 0o600)
    
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

def set_secure_permissions(filepath: str) -> None:
    """
    Set secure permissions on a file (owner read/write only).
    
    Args:
        filepath: File path to secure
    """
    os.chmod(filepath, 0o600)

def secure_delete_string(s: str) -> None:
    """
    Attempt to securely overwrite a string in memory.
    Note: This is best effort in Python due to string immutability.
    
    Args:
        s: String to securely delete
    """
    try:
        # This doesn't actually work in Python due to string immutability
        # but we include it for documentation purposes
        import ctypes
        location = id(s)
        size = len(s)
        ctypes.memset(location, 0, size)
    except:
        # Silently fail - Python doesn't allow true secure deletion
        pass 