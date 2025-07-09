"""
Layered encryption system for applying multiple encryption layers sequentially.

This module provides a flexible, modular approach for applying multiple encryption 
layers to data, allowing for combinations like standard + quantum encryption.
"""

import json
import base64
from typing import Dict, Any, List, Optional, Union
from .config import SecurityLayer
from ..security.standard_encryption import StandardEncryption
from ..security.quantum_encryption import QuantumEncryption


class LayeredEncryption:
    """
    Handles sequential application of multiple encryption layers.
    
    This class provides a modular approach where data flows through multiple
    encryption layers in sequence, with each layer wrapping the previous one.
    """
    
    def __init__(self, passphrase: str, layers: List[SecurityLayer], 
                 memory_cost: int = 524288, time_cost: int = 5, parallelism: int = 1):
        """
        Initialize the layered encryption system.
        
        Args:
            passphrase: The passphrase to use for encryption
            layers: List of security layers to apply in order
            memory_cost: Argon2 memory cost in KiB
            time_cost: Argon2 time cost
            parallelism: Argon2 parallelism
        """
        self.passphrase = passphrase
        self.layers = layers
        self.memory_cost = memory_cost
        self.time_cost = time_cost
        self.parallelism = parallelism
        
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
    
    def encrypt(self, data: bytes) -> Dict[str, Any]:
        """
        Apply all encryption layers sequentially to the data.
        
        Args:
            data: The data to encrypt
            
        Returns:
            Dictionary containing the layered encrypted data and metadata
        """
        current_data = data
        layer_results = []
        
        for layer in self.layers:
            if layer == SecurityLayer.STANDARD_ENCRYPTION:
                # Apply standard encryption
                encrypted = self.standard_enc.encrypt(current_data)
                layer_results.append({
                    "layer": "standard_encryption",
                    "data": encrypted
                })
                # Convert to bytes for next layer
                current_data = json.dumps(encrypted).encode("utf-8")
                
            elif layer == SecurityLayer.QUANTUM_ENCRYPTION:
                # Apply quantum encryption
                encrypted = self.quantum_enc.encrypt(current_data)
                layer_results.append({
                    "layer": "quantum_encryption", 
                    "data": encrypted
                })
                # Convert to bytes for next layer
                current_data = json.dumps(encrypted).encode("utf-8")
        
        return {
            "layers": [layer.value for layer in self.layers],
            "layer_results": layer_results,
            "final_data": base64.b64encode(current_data).decode("utf-8"),
            "encryption_info": self._build_encryption_info(layer_results)
        }
    
    def decrypt(self, encrypted_data: Dict[str, Any]) -> bytes:
        """
        Decrypt data by reversing all encryption layers.
        
        Args:
            encrypted_data: Dictionary containing the layered encrypted data
            
        Returns:
            The original decrypted data
        """
        layers = encrypted_data["layers"]
        
        # If no layers, just return the final data
        if not layers:
            return base64.b64decode(encrypted_data["final_data"])
        
        # Use layer_results to decrypt in reverse order
        if "layer_results" in encrypted_data:
            layer_results = encrypted_data["layer_results"]
            
            # Start with the original data from the first layer
            # and decrypt each layer in reverse order
            current_data = b""  # Initialize with empty bytes
            
            # Start from the last layer and work backwards
            for i in range(len(layers) - 1, -1, -1):
                layer = layers[i]
                layer_data = layer_results[i]["data"]
                
                if layer == "quantum_encryption":
                    # Quantum decryption
                    decrypted = self.quantum_enc.decrypt(layer_data)
                    current_data = decrypted
                    
                elif layer == "standard_encryption":
                    # Standard decryption - need to use the salt from the encrypted data
                    salt = base64.b64decode(layer_data["salt"])
                    memory_cost = int(layer_data["memory_cost"])
                    time_cost = int(layer_data["time_cost"])
                    parallelism = int(layer_data["parallelism"])
                    
                    # Create new StandardEncryption with the correct salt
                    std_enc = StandardEncryption(
                        passphrase=self.passphrase,
                        salt=salt,
                        memory_cost=memory_cost,
                        time_cost=time_cost,
                        parallelism=parallelism
                    )
                    decrypted = std_enc.decrypt(layer_data)
                    current_data = decrypted
            
            if not current_data:
                raise ValueError("No valid decryption result obtained")
            
            return current_data
        
        else:
            # Fallback for data without layer_results
            # This shouldn't happen in normal operation with new format
            raise ValueError("No layer_results found in encrypted data")
    
    def _build_encryption_info(self, layer_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build encryption info summary from layer results.
        
        Args:
            layer_results: List of layer encryption results
            
        Returns:
            Dictionary with encryption info for each layer
        """
        encryption_info = {}
        
        for layer_result in layer_results:
            layer_name = layer_result["layer"]
            layer_data = layer_result["data"]
            
            if layer_name == "standard_encryption":
                encryption_info["standard_encryption"] = {
                    "salt": layer_data["salt"],
                    "kdf": layer_data["kdf"],
                    "memory_cost": layer_data["memory_cost"],
                    "time_cost": layer_data["time_cost"],
                    "parallelism": layer_data["parallelism"],
                    "encryption_type": layer_data["encryption_type"]
                }
                
            elif layer_name == "quantum_encryption":
                encryption_info["quantum_encryption"] = {
                    "algorithm": layer_data["encryption_type"],
                    "memory_cost": layer_data["memory_cost"],
                    "time_cost": layer_data["time_cost"],
                    "parallelism": layer_data["parallelism"],
                    "key_commitment": True,
                    "hmac_combination": True,
                    "kdf": layer_data["kdf"]
                }
        
        return encryption_info
    
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
        layers = [SecurityLayer(layer) for layer in vault_data["layers"]]
        
        # Extract parameters from the first layer that has them
        memory_cost = 524288  # Default
        time_cost = 5         # Default
        parallelism = 1       # Default
        
        if "encryption_info" in vault_data:
            info = vault_data["encryption_info"]
            if "standard_encryption" in info:
                memory_cost = int(info["standard_encryption"]["memory_cost"])
                time_cost = int(info["standard_encryption"]["time_cost"])
                parallelism = int(info["standard_encryption"]["parallelism"])
            elif "quantum_encryption" in info:
                memory_cost = int(info["quantum_encryption"]["memory_cost"])
                time_cost = int(info["quantum_encryption"]["time_cost"])
                parallelism = int(info["quantum_encryption"]["parallelism"])
        
        return LayeredEncryption(
            passphrase=passphrase,
            layers=layers,
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism
        ) 