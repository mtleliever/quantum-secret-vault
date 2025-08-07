"""
Standard encryption using AES-256-GCM with Argon2id key derivation.
"""

import os
import base64
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import Type, hash_secret_raw

class StandardEncryption:
    """Standard AES-256-GCM encryption with Argon2id key derivation"""
    
    def __init__(self, passphrase: str, salt: Optional[bytes] = None, 
                 memory_cost: int = 524288, time_cost: int = 5, parallelism: int = 1):
        """
        Initialize standard encryption.
        
        Args:
            passphrase: The passphrase to derive the key from
            salt: Optional salt for key derivation (generated if not provided)
            memory_cost: Memory usage in KiB (default: 512 MiB for crypto seed security)
            time_cost: Number of iterations (default: 5)
            parallelism: Number of parallel threads (default: 1)
        """
        self.passphrase = passphrase
        self.salt = salt or os.urandom(32)
        self.memory_cost = memory_cost  # 512 MiB default
        self.time_cost = time_cost      # 5 iterations default
        self.parallelism = parallelism  # 1 thread default
        
    def derive_key(self) -> bytes:
        """Derive AES key using Argon2id with configurable parameters"""
        return hash_secret_raw(
            secret=self.passphrase.encode('utf-8'),
            salt=self.salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=32,  # 256-bit key
            type=Type.ID  # Argon2id variant (recommended)
        )
    
    def encrypt(self, data: bytes) -> Dict[str, Any]:
        """
        Encrypt data with AES-256-GCM.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Dictionary containing encrypted data and metadata
        """
        key = self.derive_key()
        nonce = os.urandom(12)
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, data, None)
        
        return {
            "encryption_type": "AES-256-GCM",
            "salt": base64.b64encode(self.salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "kdf": "Argon2id",
            "memory_cost": self.memory_cost,
            "time_cost": self.time_cost,
            "parallelism": self.parallelism
        }
    
    def decrypt(self, encrypted_data: Dict[str, Any]) -> bytes:
        """
        Decrypt data with AES-256-GCM.
        
        Args:
            encrypted_data: Dictionary containing encrypted data and metadata
            
        Returns:
            Decrypted data
        """
        key = self.derive_key()
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        cipher = AESGCM(key)
        return cipher.decrypt(nonce, ciphertext, None) 