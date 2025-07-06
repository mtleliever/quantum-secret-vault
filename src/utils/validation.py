"""
Validation utilities for the quantum secret vault.
"""

import re
from typing import List

def validate_seed_phrase(seed: str) -> bool:
    """
    Validate BIP-39 seed phrase format.
    
    Args:
        seed: Seed phrase to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not seed or not isinstance(seed, str):
        return False
    
    # Split into words
    words = seed.strip().split()
    
    # Check word count (BIP-39 supports 12, 15, 18, 21, 24 words)
    valid_lengths = [12, 15, 18, 21, 24]
    if len(words) not in valid_lengths:
        return False
    
    # Check each word is alphabetic and lowercase
    for word in words:
        if not word.isalpha() or not word.islower():
            return False
    
    return True

def validate_passphrase(passphrase: str) -> bool:
    """
    Validate BIP-39 passphrase format.
    
    Args:
        passphrase: Passphrase to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not passphrase or not isinstance(passphrase, str):
        return False
    
    # Passphrase should be reasonable length
    if len(passphrase) < 1 or len(passphrase) > 100:
        return False
    
    return True

def get_seed_word_count(seed: str) -> int:
    """
    Get the number of words in a seed phrase.
    
    Args:
        seed: Seed phrase
        
    Returns:
        Number of words
    """
    if not seed:
        return 0
    return len(seed.strip().split()) 