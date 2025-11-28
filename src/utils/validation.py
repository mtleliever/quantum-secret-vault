"""
Validation utilities for the quantum secret vault.
"""

import re
from typing import List

def validate_secret(secret: str) -> bool:
    """
    Validate secret text format.
    
    Args:
        secret: Secret text to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not secret or not isinstance(secret, str):
        return False
    
    # Secret should be non-empty
    if len(secret.strip()) == 0:
        return False
    
    return True

def validate_password(password: str) -> bool:
    """
    Validate password format.
    
    Args:
        password: Password to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not password or not isinstance(password, str):
        return False
    
    # Password should be reasonable length
    if len(password) < 1 or len(password) > 100:
        return False
    
    return True

def get_secret_length(secret: str) -> int:
    """
    Get the length of a secret.
    
    Args:
        secret: Secret text
        
    Returns:
        Length of secret
    """
    if not secret:
        return 0
    return len(secret.strip())