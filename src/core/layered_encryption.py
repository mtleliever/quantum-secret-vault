"""
Layered encryption system for applying multiple encryption layers sequentially.

This module provides a flexible, modular approach for applying multiple encryption 
layers to data, allowing for combinations like standard + quantum encryption + Shamir sharing.
"""

import json
import base64
from typing import Dict, Any, List, Optional, Union
from .config import SecurityLayer
from ..security.standard_encryption import StandardEncryption
from ..security.quantum_encryption import QuantumEncryption
from ..security.shamir_sharing import ShamirSharing


class LayeredEncryption:
    """
    Handles sequential application of multiple encryption layers.
    
    This class provides a modular approach where data flows through multiple
    encryption layers in sequence, with each layer wrapping the previous one.
    """
    
    def __init__(self, passphrase: str, layers: List[SecurityLayer], 
                 memory_cost: int = 524288, time_cost: int = 5, parallelism: int = 1,
                 shamir_threshold: int = 3, shamir_total: int = 5, parity_shares: int = 2):
        """
        Initialize the layered encryption system.
        
        Args:
            passphrase: The passphrase to use for encryption
            layers: List of security layers to apply in order
            memory_cost: Argon2 memory cost in KiB
            time_cost: Argon2 time cost
            parallelism: Argon2 parallelism
            shamir_threshold: Minimum shares needed for Shamir recovery
            shamir_total: Total number of Shamir shares to create
            parity_shares: Number of Reed-Solomon parity shares
        """
        self.passphrase = passphrase
        self.layers = layers
        self.memory_cost = memory_cost
        self.time_cost = time_cost
        self.parallelism = parallelism
        self.shamir_threshold = shamir_threshold
        self.shamir_total = shamir_total
        self.parity_shares = parity_shares
        
        # Initialize encryption instances
        self.standard_enc = StandardEncryption(
            passphrase,
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism
        )
        
        self.quantum_enc = QuantumEncryption(
            passphrase=passphrase,
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism
        )
        
        self.shamir = ShamirSharing(
            threshold=shamir_threshold,
            total=shamir_total,
            parity=parity_shares
        )
    
    def encrypt(self, data: bytes) -> Dict[str, Any]:
        """
        Apply all encryption layers sequentially to the data.
        
        Args:
            data: The data to encrypt
            
        Returns:
            Dictionary containing the layered encrypted data/shares and metadata
        """
        current_data = data
        layer_results = []
        
        # Process non-Shamir layers first
        for layer in self.layers:
            if layer == SecurityLayer.STANDARD_ENCRYPTION:
                # Apply standard encryption to current data
                encrypted = self.standard_enc.encrypt(current_data)
                
                # Store only the metadata (not the ciphertext)
                layer_results.append({
                    "layer": "standard_encryption",
                    "metadata": {
                        "salt": encrypted["salt"],
                        "nonce": encrypted["nonce"],
                        "kdf": encrypted["kdf"],
                        "memory_cost": encrypted["memory_cost"],
                        "time_cost": encrypted["time_cost"],
                        "parallelism": encrypted["parallelism"],
                        "encryption_type": encrypted["encryption_type"]
                    }
                })
                
                # The result becomes input for next layer
                current_data = base64.b64decode(encrypted["ciphertext"])
                
            elif layer == SecurityLayer.QUANTUM_ENCRYPTION:
                # Apply quantum encryption to current data
                encrypted = self.quantum_enc.encrypt(current_data)
                
                # Store only the metadata (not the ciphertext)
                layer_results.append({
                    "layer": "quantum_encryption",
                    "metadata": {
                        "kdf": encrypted["kdf"],
                        "memory_cost": encrypted["memory_cost"],
                        "time_cost": encrypted["time_cost"],
                        "parallelism": encrypted["parallelism"],
                        "encryption_type": encrypted["encryption_type"],
                        "kyber_public_key": encrypted["kyber_public_key"],
                        "kyber_ciphertext": encrypted["kyber_ciphertext"],
                        "encrypted_private_key": encrypted["encrypted_private_key"],
                        "secret_key_nonce": encrypted["secret_key_nonce"],
                        "salt": encrypted["salt"],
                        "key_commitment": encrypted["key_commitment"],
                        "aes_nonce": encrypted["aes_nonce"]
                    }
                })
                
                # The result becomes input for next layer
                current_data = base64.b64decode(encrypted["aes_ciphertext"])
        
        # Check if Shamir sharing is enabled (should be applied last)
        if SecurityLayer.SHAMIR_SHARING in self.layers:
            # Convert encrypted data to base64 string for Shamir
            encrypted_b64_string = base64.b64encode(current_data).decode("utf-8")
            
            # Split into Shamir shares
            shares = self.shamir.split_secret(encrypted_b64_string)
            
            # Add Shamir layer metadata
            layer_results.append({
                "layer": "shamir_sharing",
                "metadata": {
                    "threshold": self.shamir_threshold,
                    "total": self.shamir_total,
                    "parity": self.parity_shares,
                    "total_shares": self.shamir_total
                }
            })
            
            # Return shares instead of single ciphertext
            return {
                "layers": layer_results,
                "shares": shares
            }
        else:
            # No Shamir sharing - return single ciphertext
            return {
                "layers": layer_results,
                "ciphertext": base64.b64encode(current_data).decode("utf-8")
            }
    
    def decrypt(self, encrypted_data: Dict[str, Any]) -> bytes:
        """
        Decrypt data by reversing all encryption layers.
        
        Args:
            encrypted_data: Dictionary containing the layered encrypted data or shares
            
        Returns:
            The original decrypted data
        """
        layers = encrypted_data["layers"]
        
        # If no layers, just return the final data
        if not layers:
            if "shares" in encrypted_data:
                # Handle shares without layers (shouldn't normally happen)
                shamir = ShamirSharing(threshold=2, total=len(encrypted_data["shares"]), parity=0)
                recovered_b64 = shamir.recover_secret(encrypted_data["shares"])
                return base64.b64decode(recovered_b64)
            else:
                return base64.b64decode(encrypted_data["ciphertext"])
        
        # Determine starting data: either from shares or single ciphertext
        if "shares" in encrypted_data:
            # We have Shamir shares - need to reconstruct first
            shares = encrypted_data["shares"]
            
            # Find Shamir layer metadata to get parameters
            shamir_layer = None
            for layer_info in layers:
                if layer_info["layer"] == "shamir_sharing":
                    shamir_layer = layer_info
                    break
            
            if shamir_layer:
                metadata = shamir_layer["metadata"]
                threshold = metadata.get("threshold", len(shares) // 2 + 1)
                total = metadata.get("total", len(shares))
                parity = metadata.get("parity", 0)
            else:
                # Fallback parameters
                threshold = len(shares) // 2 + 1
                total = len(shares)
                parity = 0
            
            # Reconstruct encrypted data from shares
            shamir = ShamirSharing(threshold=threshold, total=total, parity=parity)
            recovered_b64_string = shamir.recover_secret(shares[:threshold])
            current_data = base64.b64decode(recovered_b64_string)
        else:
            # Single ciphertext - use directly
            current_data = base64.b64decode(encrypted_data["ciphertext"])
        
        # Process layers in reverse order (skip Shamir as it's already handled)
        for i in range(len(layers) - 1, -1, -1):
            layer_info = layers[i]
            layer_type = layer_info["layer"]
            layer_metadata = layer_info["metadata"]
            
            if layer_type == "shamir_sharing":
                # Shamir was already handled above, skip
                continue
            elif layer_type == "quantum_encryption":
                # Reconstruct quantum encryption data structure
                quantum_data = {
                    "kdf": layer_metadata["kdf"],
                    "memory_cost": layer_metadata["memory_cost"],
                    "time_cost": layer_metadata["time_cost"],
                    "parallelism": layer_metadata["parallelism"],
                    "encryption_type": layer_metadata["encryption_type"],
                    "kyber_public_key": layer_metadata["kyber_public_key"],
                    "kyber_ciphertext": layer_metadata["kyber_ciphertext"],
                    "encrypted_private_key": layer_metadata["encrypted_private_key"],
                    "secret_key_nonce": layer_metadata["secret_key_nonce"],
                    "salt": layer_metadata["salt"],
                    "key_commitment": layer_metadata["key_commitment"],
                    "aes_nonce": layer_metadata["aes_nonce"],
                    "aes_ciphertext": base64.b64encode(current_data).decode("utf-8")
                }
                
                # Decrypt using quantum encryption
                decrypted = self.quantum_enc.decrypt(quantum_data)
                current_data = decrypted
                
            elif layer_type == "standard_encryption":
                # Reconstruct standard encryption data structure
                standard_data = {
                    "salt": layer_metadata["salt"],
                    "nonce": layer_metadata["nonce"],
                    "kdf": layer_metadata["kdf"],
                    "memory_cost": layer_metadata["memory_cost"],
                    "time_cost": layer_metadata["time_cost"],
                    "parallelism": layer_metadata["parallelism"],
                    "encryption_type": layer_metadata["encryption_type"],
                    "ciphertext": base64.b64encode(current_data).decode("utf-8")
                }
                
                # Create StandardEncryption with correct salt and decrypt
                salt = base64.b64decode(layer_metadata["salt"])
                memory_cost = int(layer_metadata["memory_cost"])
                time_cost = int(layer_metadata["time_cost"])
                parallelism = int(layer_metadata["parallelism"])
                
                std_enc = StandardEncryption(
                    passphrase=self.passphrase,
                    salt=salt,
                    memory_cost=memory_cost,
                    time_cost=time_cost,
                    parallelism=parallelism
                )
                decrypted = std_enc.decrypt(standard_data)
                current_data = decrypted
        
        return current_data

    @staticmethod
    def create_from_vault_data(vault_data: Dict[str, Any], passphrase: str) -> 'LayeredEncryption':
        """
        Create a LayeredEncryption instance from vault data for decryption.
        
        Args:
            vault_data: The vault data containing layer information
            passphrase: The passphrase for decryption
            
        Returns:
            LayeredEncryption instance configured for decryption
        """
        layers_data = vault_data["layers"]
        layers = [SecurityLayer(layer_info["layer"]) for layer_info in layers_data]
        
        # Extract parameters from layer metadata
        memory_cost = 524288  # Default
        time_cost = 5         # Default
        parallelism = 1       # Default
        shamir_threshold = 3  # Default
        shamir_total = 5      # Default
        parity_shares = 2     # Default
        
        # Extract parameters from the first layer that has them
        for layer_info in layers_data:
            layer_metadata = layer_info["metadata"]
            layer_type = layer_info["layer"]
            
            # Extract encryption parameters
            if "memory_cost" in layer_metadata:
                memory_cost = int(layer_metadata["memory_cost"])
                time_cost = int(layer_metadata["time_cost"])
                parallelism = int(layer_metadata["parallelism"])
            
            # Extract Shamir parameters
            if layer_type == "shamir_sharing":
                shamir_threshold = int(layer_metadata.get("threshold", 3))
                shamir_total = int(layer_metadata.get("total", 5))
                parity_shares = int(layer_metadata.get("parity", 2))
        
        return LayeredEncryption(
            passphrase=passphrase,
            layers=layers,
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            shamir_threshold=shamir_threshold,
            shamir_total=shamir_total,
            parity_shares=parity_shares
        ) 