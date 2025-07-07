"""
Standard encryption using AES-256-GCM with PBKDF2 key derivation.
"""

import os
import base64
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class StandardEncryption:
    """Standard AES-256-GCM encryption with PBKDF2 key derivation"""
    
    def __init__(self, passphrase: str, salt: Optional[bytes] = None, iterations: int = 2000000):
        """
        Initialize standard encryption.
        
        Args:
            passphrase: The passphrase to derive the key from
            salt: Optional salt for key derivation (generated if not provided)
            iterations: PBKDF2 iteration count (default: 2M for very high security)
        """
        self.passphrase = passphrase
        self.salt = salt or os.urandom(32)
        self.iterations = iterations
        
    def derive_key(self) -> bytes:
        """Derive AES key using PBKDF2 with configurable iteration count"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=self.salt,
            iterations=self.iterations,  # Configurable iteration count
        )
        return kdf.derive(self.passphrase.encode('utf-8'))
    
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
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": str(self.iterations)
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