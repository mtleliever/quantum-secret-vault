"""
Main vault class implementing layered security.
"""

import os
import json
import datetime
from typing import List, Dict, Any, Optional

from ..security.standard_encryption import StandardEncryption
from ..security.quantum_encryption import QuantumEncryption
from ..security.shamir_sharing import ShamirSharing
from ..security.steganography import Steganography
from .config import SecurityConfig, SecurityLayer

class QuantumSecretVault:
    """Main vault class implementing layered security"""
    
    def __init__(self, config: SecurityConfig):
        """
        Initialize quantum secret vault.
        
        Args:
            config: Security configuration with layers and parameters
        """
        self.config = config
        self.standard_enc = StandardEncryption(config.passphrase, config.salt)
        self.quantum_enc = QuantumEncryption()
        self.shamir = ShamirSharing(config.shamir_threshold, config.shamir_total, config.parity_shares)
        self.stego = Steganography()
        
    def encrypt_seed(self, seed: str) -> Dict[str, Any]:
        """
        Encrypt seed using selected security layers.
        
        Args:
            seed: Seed string to encrypt
            
        Returns:
            Dictionary with encrypted data and metadata
        """
        current_data = seed.encode('utf-8')
        encryption_info = {}
        
        # Layer 1: Standard Encryption (if enabled)
        if self.config.has_layer(SecurityLayer.STANDARD_ENCRYPTION):
            encrypted = self.standard_enc.encrypt(current_data)
            current_data = json.dumps(encrypted).encode('utf-8')
            encryption_info["standard_encryption"] = {
                "salt": encrypted["salt"],
                "kdf": encrypted["kdf"],
                "iterations": encrypted["iterations"]
            }
        
        # Layer 2: Quantum Encryption (if enabled)
        if self.config.has_layer(SecurityLayer.QUANTUM_ENCRYPTION):
            encrypted = self.quantum_enc.encrypt(current_data)
            current_data = json.dumps(encrypted).encode('utf-8')
            encryption_info["quantum_encryption"] = {
                "kem": "Kyber1024",
                "requires_private_key": True
            }
        
        # Layer 3: Shamir Secret Sharing (if enabled)
        if self.config.has_layer(SecurityLayer.SHAMIR_SHARING):
            shares = self.shamir.split_secret(current_data.decode('utf-8'))
            encryption_info["shamir_sharing"] = {
                "threshold": self.config.shamir_threshold,
                "total": self.config.shamir_total,
                "parity": self.config.parity_shares,
                "shares_count": len(shares)
            }
            return {
                "shares": shares,
                "encryption_info": encryption_info,
                "layers_used": [layer.value for layer in self.config.layers]
            }
        else:
            # No sharing, return single encrypted data
            return {
                "encrypted_data": current_data.decode('utf-8'),
                "encryption_info": encryption_info,
                "layers_used": [layer.value for layer in self.config.layers]
            }
    
    def create_vault(self, seed: str, output_dir: str, images: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Create the complete vault with all selected layers.
        
        Args:
            seed: Seed string to protect
            output_dir: Directory to create vault in
            images: Optional list of image paths for steganography
            
        Returns:
            Dictionary with vault creation information
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Create subdirectories based on layers
        if self.config.has_layer(SecurityLayer.QUANTUM_ENCRYPTION):
            os.makedirs(f"{output_dir}/quantum_keys", exist_ok=True)
        if self.config.has_layer(SecurityLayer.SHAMIR_SHARING):
            os.makedirs(f"{output_dir}/shares", exist_ok=True)
        if self.config.has_layer(SecurityLayer.STEGANOGRAPHY):
            os.makedirs(f"{output_dir}/stego_images", exist_ok=True)
        
        # Encrypt the seed
        result = self.encrypt_seed(seed)
        
        vault_info = {
            "vault_created": True,
            "layers_used": result["layers_used"],
            "encryption_info": result["encryption_info"],
            "files_created": []
        }
        
        # Handle different output formats based on layers
        if self.config.has_layer(SecurityLayer.SHAMIR_SHARING):
            # Multiple shares
            shares = result["shares"]
            for i, share in enumerate(shares):
                share_file = f"{output_dir}/shares/share_{i}.json"
                with open(share_file, 'w') as f:
                    json.dump({
                        "share_id": i,
                        "share_type": "Shamir" if i < self.config.shamir_total else "Parity",
                        "data": share.decode('utf-8') if isinstance(share, bytes) else share,
                        "encryption_info": result["encryption_info"]
                    }, f, indent=2)
                vault_info["files_created"].append(share_file)
                
                # Add steganography if enabled
                if self.config.has_layer(SecurityLayer.STEGANOGRAPHY) and images and i < len(images):
                    stego_file = f"{output_dir}/stego_images/share_{i}.png"
                    if self.stego.embed_data(share_file, images[i], stego_file):
                        vault_info["files_created"].append(stego_file)
        else:
            # Single encrypted file
            encrypted_file = f"{output_dir}/encrypted_seed.json"
            with open(encrypted_file, 'w') as f:
                json.dump({
                    "encrypted_data": result["encrypted_data"],
                    "encryption_info": result["encryption_info"]
                }, f, indent=2)
            vault_info["files_created"].append(encrypted_file)
            
            # Add steganography if enabled
            if self.config.has_layer(SecurityLayer.STEGANOGRAPHY) and images:
                stego_file = f"{output_dir}/stego_images/encrypted_seed.png"
                if self.stego.embed_data(encrypted_file, images[0], stego_file):
                    vault_info["files_created"].append(stego_file)
        
        # Save vault configuration
        config_file = f"{output_dir}/vault_config.json"
        with open(config_file, 'w') as f:
            json.dump({
                "layers": [layer.value for layer in self.config.layers],
                "shamir_config": {
                    "threshold": self.config.shamir_threshold,
                    "total": self.config.shamir_total,
                    "parity": self.config.parity_shares
                } if self.config.has_layer(SecurityLayer.SHAMIR_SHARING) else None,
                "created_timestamp": str(datetime.datetime.now())
            }, f, indent=2)
        vault_info["files_created"].append(config_file)
        
        return vault_info 