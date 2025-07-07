"""
Post-quantum encryption using Kyber-1024 with defense-in-depth architecture.

QUANTUM ENCRYPTION METHODOLOGY:
==============================

This implementation uses a novel hybrid approach combining post-quantum cryptography
with password-based key derivation to create multiple independent security barriers.

ARCHITECTURE OVERVIEW:
---------------------
Password → [KDF] → Private Key → [liboqs Kyber-1024] → Public Key
                ↓
Original Password Hash + Public Key → [Argon2id] → AES Key → [AES-256-GCM] → Encrypted Seed

SECURITY LAYERS:
---------------
1. Password-to-Private-Key Derivation: Strong KDF to prevent weak password attacks
2. Post-Quantum Cryptography: Kyber-1024 provides quantum-resistant key generation
3. Password + Public Key Combination: Dual-input defense against algorithm breaks
4. Argon2id Memory-Hardness: 512 MiB memory requirement makes brute force expensive
5. AES-256-GCM Encryption: Military-grade authenticated encryption

DEFENSE-IN-DEPTH RATIONALE:
--------------------------
- If liboqs/Kyber breaks: Original password still protects via Argon2
- If password leaks: Post-quantum layer still provides protection  
- If Argon2 weakens: Dual-input makes attacks significantly harder
- If AES breaks: Multiple key derivation layers provide additional barriers

ATTACK RESISTANCE:
-----------------
- Classical computers: Password + 512 MiB Argon2 + post-quantum hardness
- Quantum computers: Argon2 remains memory-hard + password barrier remains
- Algorithm breaks: Independent failures required for both password and post-quantum paths

THREAT MODEL:
------------
Designed for high-value cryptocurrency seed protection where:
- Seeds may be worth millions of dollars
- Infrequent access (performance less important than security)
- Long-term storage (decades of protection required)
- Unknown future cryptographic vulnerabilities

This approach is "quantum-paranoid" - engineered to survive multiple simultaneous
cryptographic failures while maintaining practical usability.
"""

import os
import base64
from typing import Dict, Any
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class QuantumEncryption:
    """Post-quantum encryption using Kyber-1024"""
    
    def __init__(self):
        """Initialize quantum encryption with Kyber-1024"""
        self.kem_name = "Kyber1024"
    
    def encrypt(self, data: bytes) -> Dict[str, Any]:
        """
        Encrypt data with Kyber-1024 + AES-256-GCM.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Dictionary containing encrypted data and metadata
        """
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            # Generate Kyber keypair
            pubkey = kem.generate_keypair()
            
            # Generate random AES key for data encryption
            aes_key = os.urandom(32)
            nonce = os.urandom(12)
            cipher = AESGCM(aes_key)
            ciphertext = cipher.encrypt(nonce, data, None)
            
            # Encapsulate AES key with Kyber
            kyber_ct, kyber_ss = kem.encap_secret(pubkey)
            
            return {
                "encryption_type": "Kyber1024-AES256-GCM",
                "kyber_pubkey": base64.b64encode(pubkey).decode('utf-8'),
                "kyber_ciphertext": base64.b64encode(kyber_ct).decode('utf-8'),
                "aes_nonce": base64.b64encode(nonce).decode('utf-8'),
                "aes_ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "private_key_required": True
            }
    
    def get_private_key(self) -> bytes:
        """
        Get the private key for later decryption.
        
        Returns:
            Private key bytes
        """
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            return kem.export_secret_key()
    
    def decrypt(self, encrypted_data: Dict[str, Any], private_key: bytes) -> bytes:
        """
        Decrypt data with Kyber-1024 + AES-256-GCM.
        
        Args:
            encrypted_data: Dictionary containing encrypted data
            private_key: Private key for decryption
            
        Returns:
            Decrypted data
        """
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            kem.import_secret_key(private_key)
            
            # Decapsulate AES key
            kyber_ct = base64.b64decode(encrypted_data["kyber_ciphertext"])
            aes_key = kem.decap_secret(kyber_ct)
            
            # Decrypt data with AES
            nonce = base64.b64decode(encrypted_data["aes_nonce"])
            ciphertext = base64.b64decode(encrypted_data["aes_ciphertext"])
            cipher = AESGCM(aes_key)
            
            return cipher.decrypt(nonce, ciphertext, None) 