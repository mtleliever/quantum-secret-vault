"""
Utility functions for the quantum secret vault.
"""

from .validation import validate_seed_phrase, validate_passphrase
from .file_utils import (
    ensure_directory, 
    safe_write_json, 
    safe_read_json,
    set_secure_permissions,
    set_secure_directory_permissions,
    validate_path,
    PathTraversalError,
    SecureBytes,
    secure_zero_bytearray,
    secure_delete_string  # Deprecated, kept for backward compatibility
)

__all__ = [
    'validate_seed_phrase', 
    'validate_passphrase', 
    'ensure_directory', 
    'safe_write_json',
    'safe_read_json',
    'set_secure_permissions',
    'set_secure_directory_permissions',
    'validate_path',
    'PathTraversalError',
    'SecureBytes',
    'secure_zero_bytearray',
    'secure_delete_string'
]
