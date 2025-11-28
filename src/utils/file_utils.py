"""
File utility functions for the quantum secret vault.
"""

import os
import json
import tempfile
import platform
import stat
from typing import Any, Dict, Optional
from pathlib import Path


class PathTraversalError(Exception):
    """Raised when a path traversal attack is detected."""
    pass


def validate_path(path: str, allowed_base: Optional[str] = None) -> str:
    """
    Validate and sanitize a file path to prevent path traversal attacks.
    
    Args:
        path: The path to validate
        allowed_base: Optional base directory that the path must be within.
                     If None, only basic sanitization is performed.
        
    Returns:
        The canonicalized, validated path
        
    Raises:
        PathTraversalError: If path traversal is detected
        ValueError: If path is invalid
    """
    if not path:
        raise ValueError("Path cannot be empty")
    
    # Convert to Path object for safer manipulation
    try:
        # Resolve to absolute path, following symlinks
        resolved = Path(path).resolve()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid path: {e}")
    
    # Check for null bytes (injection attack)
    if '\x00' in str(path):
        raise PathTraversalError("Null bytes not allowed in path")
    
    # If an allowed base is specified, ensure the path is within it
    if allowed_base is not None:
        try:
            base_resolved = Path(allowed_base).resolve()
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid base path: {e}")
        
        # Check if resolved path is within the allowed base
        try:
            resolved.relative_to(base_resolved)
        except ValueError:
            raise PathTraversalError(
                f"Path '{path}' resolves outside allowed directory '{allowed_base}'"
            )
    
    return str(resolved)


def ensure_directory(path: str, allowed_base: Optional[str] = None) -> str:
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        path: Directory path to ensure exists
        allowed_base: Optional base directory for path validation
        
    Returns:
        The validated, canonicalized path
    """
    validated_path = validate_path(path, allowed_base)
    os.makedirs(validated_path, exist_ok=True)
    return validated_path


def set_secure_permissions(filepath: str) -> None:
    """
    Set secure permissions on a file (owner read/write only).
    Works on both Windows and Unix systems.
    
    Args:
        filepath: File path to secure
    """
    if platform.system() == 'Windows':
        _set_windows_permissions(filepath)
    else:
        # Unix-like systems
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  # 0o600


def set_secure_directory_permissions(dirpath: str) -> None:
    """
    Set secure permissions on a directory (owner read/write/execute only).
    Works on both Windows and Unix systems.
    
    Args:
        dirpath: Directory path to secure
    """
    if platform.system() == 'Windows':
        _set_windows_directory_permissions(dirpath)
    else:
        # Unix-like systems
        os.chmod(dirpath, stat.S_IRWXU)  # 0o700


def _set_windows_permissions(filepath: str) -> None:
    """
    Set secure file permissions on Windows using icacls.
    Removes inherited permissions and grants only the current user access.
    
    Args:
        filepath: File path to secure
    """
    import subprocess
    
    try:
        # Get current username
        username = os.environ.get('USERNAME', os.environ.get('USER', ''))
        if not username:
            # Fallback: try to get from whoami
            result = subprocess.run(['whoami'], capture_output=True, text=True, check=True)
            username = result.stdout.strip()
        
        # Disable inheritance and remove all inherited ACEs
        subprocess.run(
            ['icacls', filepath, '/inheritance:r'],
            capture_output=True,
            check=True
        )
        
        # Grant only the current user full control
        subprocess.run(
            ['icacls', filepath, '/grant:r', f'{username}:(F)'],
            capture_output=True,
            check=True
        )
        
    except subprocess.CalledProcessError:
        # If icacls fails, try using attrib to at least hide the file
        try:
            subprocess.run(['attrib', '+H', filepath], capture_output=True)
        except Exception:
            pass
    except Exception:
        # Silently fail if we can't set permissions
        # This is a best-effort security measure
        pass


def _set_windows_directory_permissions(dirpath: str) -> None:
    """
    Set secure directory permissions on Windows using icacls.
    
    Args:
        dirpath: Directory path to secure
    """
    import subprocess
    
    try:
        # Get current username
        username = os.environ.get('USERNAME', os.environ.get('USER', ''))
        if not username:
            result = subprocess.run(['whoami'], capture_output=True, text=True, check=True)
            username = result.stdout.strip()
        
        # Disable inheritance and remove all inherited ACEs
        subprocess.run(
            ['icacls', dirpath, '/inheritance:r'],
            capture_output=True,
            check=True
        )
        
        # Grant only the current user full control (with inheritance to children)
        subprocess.run(
            ['icacls', dirpath, '/grant:r', f'{username}:(OI)(CI)(F)'],
            capture_output=True,
            check=True
        )
        
    except Exception:
        # Silently fail - best effort security measure
        pass


def safe_write_json(data: Dict[str, Any], filepath: str, indent: int = 2,
                    allowed_base: Optional[str] = None) -> None:
    """
    Safely write JSON data to a file using atomic write with secure permissions.
    
    Args:
        data: Data to write
        filepath: Target file path
        indent: JSON indentation
        allowed_base: Optional base directory for path validation
    """
    # Validate the path
    validated_path = validate_path(filepath, allowed_base)
    
    # Create directory if it doesn't exist
    dir_path = os.path.dirname(validated_path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    
    # Write to temporary file first
    with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=dir_path or '.') as temp_file:
        json.dump(data, temp_file, indent=indent)
        temp_path = temp_file.name
    
    # Set secure permissions on temp file
    set_secure_permissions(temp_path)
    
    # Atomic move to final location
    os.replace(temp_path, validated_path)


def safe_read_json(filepath: str, allowed_base: Optional[str] = None) -> Dict[str, Any]:
    """
    Safely read JSON data from a file.
    
    Args:
        filepath: File path to read from
        allowed_base: Optional base directory for path validation
        
    Returns:
        Parsed JSON data
        
    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file contains invalid JSON
        PathTraversalError: If path validation fails
    """
    validated_path = validate_path(filepath, allowed_base)
    with open(validated_path, 'r') as f:
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


class SecureBytes:
    """
    A wrapper around bytearray that securely zeros memory on deletion.
    Use this for sensitive data like passwords, keys, and secrets.
    
    Usage:
        with SecureBytes(b"sensitive data") as secure:
            # Use secure.data
            pass
        # Data is automatically zeroed
    """
    
    def __init__(self, data: bytes = b""):
        """
        Initialize with data.
        
        Args:
            data: Initial data (will be copied to internal bytearray)
        """
        self._data = bytearray(data)
    
    @property
    def data(self) -> bytearray:
        """Get the underlying bytearray."""
        return self._data
    
    def __bytes__(self) -> bytes:
        """Convert to bytes (creates a copy)."""
        return bytes(self._data)
    
    def __len__(self) -> int:
        return len(self._data)
    
    def __enter__(self) -> 'SecureBytes':
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.secure_zero()
    
    def __del__(self) -> None:
        self.secure_zero()
    
    def secure_zero(self) -> None:
        """Securely zero the internal buffer."""
        if hasattr(self, '_data') and self._data is not None:
            for i in range(len(self._data)):
                self._data[i] = 0
            self._data = bytearray()


def secure_zero_bytearray(data: bytearray) -> None:
    """
    Securely zero a bytearray in-place.
    
    Args:
        data: bytearray to zero
    """
    for i in range(len(data)):
        data[i] = 0


# Deprecated - kept for backward compatibility but does nothing useful
def secure_delete_string(s: str) -> None:
    """
    DEPRECATED: This function cannot securely delete Python strings.
    
    Python strings are immutable, meaning:
    1. The string content cannot be overwritten in place
    2. Multiple copies may exist in memory due to string interning
    3. The garbage collector handles deallocation non-deterministically
    
    Use SecureBytes or bytearray for sensitive data instead.
    
    Args:
        s: String (ignored - this function is a no-op for safety)
    """
    # Intentionally does nothing - this function is kept only for backward
    # compatibility but is a no-op to avoid giving false security impressions
    pass
