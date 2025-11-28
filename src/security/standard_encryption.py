"""
Standard encryption using AES-256-GCM with Argon2id key derivation.
"""

import os
import base64
import time
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import Type, hash_secret_raw


def _secure_zero(data: bytearray) -> None:
    """Securely zero out a bytearray."""
    for i in range(len(data)):
        data[i] = 0


class StandardEncryption:
    """
    Standard AES-256-GCM encryption with Argon2id key derivation.
    
    Security: Password is stored as bytearray for secure zeroing.
    """
    
    def __init__(self, password: str, salt: Optional[bytes] = None, 
                 memory_cost: int = 524288, time_cost: int = 5, parallelism: int = 1):
        """
        Initialize standard encryption.
        
        Args:
            password: The password to derive the key from
            salt: Optional salt for key derivation (generated if not provided)
            memory_cost: Memory usage in KiB (default: 512 MiB for security)
            time_cost: Number of iterations (default: 5)
            parallelism: Number of parallel threads (default: 1)
        """
        # Store password as bytearray for secure zeroing later
        self._password_bytes = bytearray(password.encode('utf-8'))
        self.salt = salt or os.urandom(32)
        self.memory_cost = memory_cost  # 512 MiB default
        self.time_cost = time_cost      # 5 iterations default
        self.parallelism = parallelism  # 1 thread default
    
    def __del__(self):
        """Securely zero password bytes on destruction."""
        if hasattr(self, '_password_bytes'):
            _secure_zero(self._password_bytes)
    
    def _derive_key(self) -> bytearray:
        """
        Derive AES key using Argon2id with configurable parameters.
        
        Returns:
            32-byte derived key as bytearray for secure zeroing
        """
        derived = hash_secret_raw(
            secret=bytes(self._password_bytes),
            salt=self.salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=32,  # 256-bit key
            type=Type.ID  # Argon2id variant (recommended)
        )
        return bytearray(derived)
    
    def encrypt(self, data: bytes) -> Dict[str, Any]:
        """
        Encrypt data with AES-256-GCM.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Dictionary containing encrypted data and metadata
        """
        key = self._derive_key()
        
        try:
            nonce = os.urandom(12)
            cipher = AESGCM(bytes(key))
            
            # Build AAD to bind ciphertext to its metadata
            aad = b"standard-vault-v2:" + self.salt
            
            ciphertext = cipher.encrypt(nonce, data, aad)
            
            return {
                "encryption_type": "AES-256-GCM",
                "version": "2.0",  # Version bump for AAD support
                "salt": base64.b64encode(self.salt).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "kdf": "Argon2id",
                "memory_cost": self.memory_cost,
                "time_cost": self.time_cost,
                "parallelism": self.parallelism
            }
        finally:
            # Securely zero the derived key
            _secure_zero(key)
    
    def decrypt(self, encrypted_data: Dict[str, Any]) -> bytes:
        """
        Decrypt data with AES-256-GCM.
        
        Args:
            encrypted_data: Dictionary containing encrypted data and metadata
            
        Returns:
            Decrypted data
            
        Raises:
            ValueError: If decryption fails (generic message to prevent information leakage)
        """
        key = self._derive_key()
        
        try:
            nonce = base64.b64decode(encrypted_data["nonce"])
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            cipher = AESGCM(bytes(key))
            
            # Check version to determine AAD usage
            version = encrypted_data.get("version", "1.0")
            if version >= "2.0":
                # New format with AAD
                aad = b"standard-vault-v2:" + self.salt
            else:
                # Legacy format without AAD
                aad = None
            
            return cipher.decrypt(nonce, ciphertext, aad)
        except Exception:
            # Add small delay to prevent timing attacks
            time.sleep(0.1)
            # Generic error message - don't leak specific failure reason
            raise ValueError("Decryption failed: invalid password or corrupted data")
        finally:
            # Securely zero the derived key
            _secure_zero(key)
