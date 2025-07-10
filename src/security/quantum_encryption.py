import base64
import secrets
import time
import hmac
import hashlib
from typing import Dict, Any
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class QuantumEncryption:
    """
    Quantum-resistant hybrid encryption using Kyber-1024 + AES-256-GCM.
    
    This implementation properly separates password-based and post-quantum
    security layers to avoid entropy vulnerabilities.
    """
    
    def __init__(self, passphrase: str, memory_cost: int = 1048576, 
                 time_cost: int = 5, parallelism: int = 1, auto_tune: bool = True):
        """
        Initialize quantum encryption with Kyber-1024
        
        Args:
            passphrase: The passphrase to derive keys from
            memory_cost: Argon2 memory cost in KiB (default: 1GB)
            time_cost: Argon2 time cost (default: 5)
            parallelism: Argon2 parallelism (default: 1) 
            auto_tune: Whether to auto-tune Argon2 parameters for 500-1000ms
        """
        self.passphrase = passphrase
        self.kem_name = "Kyber1024"
        self.time_cost = time_cost
        self.memory_cost = memory_cost # 1GB default for high-value data
        self.parallelism = parallelism
    
    def derive_key(self, salt: bytes) -> bytes:
        """
        Derive keys using Argon2id with configurable parameters.
        
        Args:
            salt: Salt for key derivation
            
        Returns:
            64-byte derived key (32 bytes for private key encryption + 32 bytes for commitment)
        """
        return hash_secret_raw(
            secret=self.passphrase.encode('utf-8'),
            salt=salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=64,  # Need 64 bytes for private key encryption + key commitment
            type=Type.ID  # Argon2id variant (recommended)
        )
    
    def encrypt(self, data: bytes) -> Dict[str, Any]:
        """
        Encrypt data using hybrid password + post-quantum approach.
        
        Architecture:
        1. Password → Argon2 → Password-Derived Key
        2. Random → Kyber Keygen → Public/Private Key Pair  
        3. Password-Derived Key → AES → Encrypted Private Key (stored securely)
        4. Random Data Key → Kyber Encapsulate → Shared Secret
        5. Shared Secret → AES → Encrypted Data
        
        Args:
            data: Data to encrypt
            
        Returns:
            Dictionary containing all encrypted data and metadata
        """
        # Generate salt for key derivation
        salt = secrets.token_bytes(32)
        password_derived_key = self.derive_key(salt)
        
        # Split derived key for different purposes
        private_key_encryption_key = password_derived_key[:32]
        commitment_key = password_derived_key[32:64]
        
        # Generate truly random Kyber keypair
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            
            # Encrypt the secret key with password-derived key for storage
            secret_key_nonce = secrets.token_bytes(12)
            secret_key_cipher = AESGCM(private_key_encryption_key)
            encrypted_secret_key = secret_key_cipher.encrypt(secret_key_nonce, secret_key, None)
            
            # Encapsulate a random secret with Kyber public key
            kyber_ciphertext, shared_secret = kem.encap_secret(public_key)
            
            # Combine commitment key with shared secret for additional security
            combined_key = self._combine_keys_hmac(commitment_key, shared_secret)
            
            # Generate key commitment for tampering detection
            key_commitment = self._generate_key_commitment(combined_key)
            
            # Encrypt the actual data with the combined key
            data_nonce = secrets.token_bytes(12)
            data_cipher = AESGCM(combined_key[:32])
            data_ciphertext = data_cipher.encrypt(data_nonce, data, None)
            
            return {
                "encryption_type": "Kyber1024",
                "kyber_public_key": base64.b64encode(public_key).decode(),
                "kyber_ciphertext": base64.b64encode(kyber_ciphertext).decode(),
                "encrypted_private_key": base64.b64encode(encrypted_secret_key).decode(),
                "secret_key_nonce": base64.b64encode(secret_key_nonce).decode(),
                "salt": base64.b64encode(salt).decode(),
                "memory_cost": self.memory_cost,
                "time_cost": self.time_cost,
                "parallelism": self.parallelism,
                "kdf": "Argon2id",
                "key_commitment": base64.b64encode(key_commitment).decode(),
                "aes_nonce": base64.b64encode(data_nonce).decode(),
                "aes_ciphertext": base64.b64encode(data_ciphertext).decode()
            }
    
    def decrypt(self, encrypted_data: Dict[str, Any]) -> bytes:
        """
        Decrypt data using hybrid password + post-quantum approach.
        
        Args:
            encrypted_data: Dictionary containing encrypted data and metadata
            
        Returns:
            Decrypted data
        """
        # Extract components - let KeyError propagate for missing fields
        kyber_ciphertext = base64.b64decode(encrypted_data["kyber_ciphertext"])
        encrypted_private_key = base64.b64decode(encrypted_data["encrypted_private_key"])
        secret_key_nonce = base64.b64decode(encrypted_data["secret_key_nonce"])
        salt = base64.b64decode(encrypted_data["salt"])
        stored_commitment = base64.b64decode(encrypted_data["key_commitment"])
        data_ciphertext = base64.b64decode(encrypted_data["aes_ciphertext"])
        data_nonce = base64.b64decode(encrypted_data["aes_nonce"])
        
        try:
            # Derive key from stored parameters
            password_derived_key = self.derive_key(salt)
            
            # Split derived key for different purposes
            private_key_encryption_key = password_derived_key[:32]
            commitment_key = password_derived_key[32:64]
            
            # Decrypt the Kyber secret key using password-derived key
            secret_key_cipher = AESGCM(private_key_encryption_key)
            secret_key = secret_key_cipher.decrypt(secret_key_nonce, encrypted_private_key, None)
            
            # Use Kyber to recover shared secret
            with oqs.KeyEncapsulation(self.kem_name, secret_key=secret_key) as kem:
                shared_secret = kem.decap_secret(kyber_ciphertext)
            
            # Combine commitment key with shared secret
            combined_key = self._combine_keys_hmac(commitment_key, shared_secret)
            
            # Verify key commitment to detect tampering
            expected_commitment = self._generate_key_commitment(combined_key)
            if not self._constant_time_compare(stored_commitment, expected_commitment):
                raise ValueError("Key commitment verification failed - data may be tampered")
            
            # Decrypt the actual data
            data_cipher = AESGCM(combined_key[:32])
            return data_cipher.decrypt(data_nonce, data_ciphertext, None)
            
        except KeyError:
            # Re-raise KeyError for missing fields (expected by tests)
            raise
        except Exception as e:
            # Add small delay to prevent timing attacks
            time.sleep(0.1)
            raise ValueError(f"Decryption failed: {e}")
    
    def _combine_keys_hmac(self, password_key: bytes, shared_secret: bytes) -> bytes:
        """
        Securely combine password-derived key with post-quantum shared secret using HMAC.
        
        Uses HMAC-SHA256 which is more resilient against partial compromises than XOR.
        """
        # Use HMAC-SHA256 for secure key combination
        # This is more secure than XOR as it provides better avalanche effect
        combined_key = hmac.new(password_key, shared_secret, hashlib.sha256).digest()
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b"quantum-vault-hmac-expansion",
            info=b"combined-key-expansion-v2.2"
        )
        
        return hkdf.derive(combined_key)
    
    def _generate_key_commitment(self, combined_key: bytes) -> bytes:
        """
        Generate a key commitment for tampering detection.
        
        Args:
            combined_key: The combined encryption key
            
        Returns:
            32-byte key commitment
        """
        return hmac.new(b"commit", combined_key, hashlib.sha256).digest()
    
    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison to prevent timing attacks.
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            True if equal, False otherwise
        """
        return hmac.compare_digest(a, b)
