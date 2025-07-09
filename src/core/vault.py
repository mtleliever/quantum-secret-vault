"""
Main vault class implementing layered security.
"""

import os
import json
import datetime
import base64
import cbor2
from typing import List, Dict, Any, Optional
from ..security.standard_encryption import StandardEncryption
from ..security.quantum_encryption import (
    QuantumEncryption,
)  # Now enabled with liboqs properly installed
from ..security.shamir_sharing import ShamirSharing
from ..security.steganography import Steganography
from .config import SecurityConfig, SecurityLayer
from .layered_encryption import LayeredEncryption
from ..utils.file_utils import set_secure_permissions


class QuantumSecretVault:
    """Main vault class implementing layered security"""

    def __init__(self, config: SecurityConfig):
        """
        Initialize quantum secret vault.

        Args:
            config: Security configuration with layers and parameters
        """
        self.config = config
        self.standard_enc = StandardEncryption(
            config.passphrase,
            config.salt,
            config.argon2_memory_cost,
            config.argon2_time_cost,
            config.argon2_parallelism,
        )
        self.quantum_enc = QuantumEncryption(
            passphrase=config.passphrase,
            memory_cost=config.argon2_memory_cost,
            time_cost=config.argon2_time_cost,
            parallelism=config.argon2_parallelism,
        )
        self.shamir = ShamirSharing(
            config.shamir_threshold, config.shamir_total, config.parity_shares
        )
        self.stego = Steganography()

    def encrypt_seed(self, seed: str) -> Dict[str, Any]:
        """
        Encrypt seed using selected security layers in a modular, layered approach.

        Args:
            seed: Seed string to encrypt

        Returns:
            Dictionary with encrypted data and metadata
        """
        # Get encryption layers (excluding Shamir and Steganography for now)
        encryption_layers = [
            layer for layer in self.config.layers 
            if layer in [SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.QUANTUM_ENCRYPTION]
        ]
        
        # Apply layered encryption if any encryption layers are enabled
        if encryption_layers:
            layered_enc = LayeredEncryption(
                passphrase=self.config.passphrase,
                layers=encryption_layers,
                memory_cost=self.config.argon2_memory_cost,
                time_cost=self.config.argon2_time_cost,
                parallelism=self.config.argon2_parallelism
            )
            
            # Encrypt the seed through all layers
            encrypted_result = layered_enc.encrypt(seed.encode("utf-8"))
            
            # Handle Shamir Secret Sharing if enabled
            if self.config.has_layer(SecurityLayer.SHAMIR_SHARING):
                # Apply Shamir to the final encrypted data
                shares = self.shamir.split_secret(encrypted_result["final_data"])
                encrypted_result["shares"] = shares
                encrypted_result["encryption_info"]["shamir_sharing"] = {
                    "threshold": self.config.shamir_threshold,
                    "total": self.config.shamir_total,
                    "parity": self.config.parity_shares,
                    "shares_count": len(shares),
                }
            
            return encrypted_result
        else:
            # No encryption layers, just handle Shamir if enabled
            if self.config.has_layer(SecurityLayer.SHAMIR_SHARING):
                shares = self.shamir.split_secret(seed)
                return {
                    "layers": [layer.value for layer in self.config.layers],
                    "shares": shares,
                    "encryption_info": {
                        "shamir_sharing": {
                            "threshold": self.config.shamir_threshold,
                            "total": self.config.shamir_total,
                            "parity": self.config.parity_shares,
                            "shares_count": len(shares),
                        }
                    }
                }
            else:
                # No layers at all - just return the seed
                return {
                    "layers": [],
                    "final_data": base64.b64encode(seed.encode("utf-8")).decode("utf-8"),
                    "encryption_info": {}
                }

    def create_vault(
        self, seed: str, output_dir: str, images: Optional[List[str]] = None
    ) -> Dict[str, Any]:
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
        # Set secure permissions on output directory
        os.chmod(output_dir, 0o700)

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
            "layers": result["layers"],
            "encryption_info": result["encryption_info"],
            "files_created": [],
        }
        
        # Add layer_results if available
        if "layer_results" in result:
            vault_info["layer_results"] = result["layer_results"]

        # Handle different output formats based on layers
        if self.config.has_layer(SecurityLayer.SHAMIR_SHARING):
            # Multiple shares
            shares = result["shares"]
            for i, share in enumerate(shares):
                share_file = f"{output_dir}/shares/share_{i}.json"
                with open(share_file, "w") as f:
                    json.dump(
                        {
                            "share_id": i,
                            "share_type": (
                                "Shamir" if i < self.config.shamir_total else "Parity"
                            ),
                            "data": (
                                share.decode("utf-8")
                                if isinstance(share, bytes)
                                else share
                            ),
                            "encryption_info": result["encryption_info"],
                            "layers": result["layers"],
                            "layer_results": result.get("layer_results", [])
                        },
                        f,
                        indent=2,
                    )
                vault_info["files_created"].append(share_file)

                # Add steganography if enabled
                if (
                    self.config.has_layer(SecurityLayer.STEGANOGRAPHY)
                    and images
                    and i < len(images)
                ):
                    stego_file = f"{output_dir}/stego_images/share_{i}.png"
                    if self.stego.embed_data(share_file, images[i], stego_file):
                        vault_info["files_created"].append(stego_file)
        else:
            # Single encrypted file (CBOR binary)
            vault_bin_file = f"{output_dir}/vault.bin"
            cbor_data = {
                "layers": result["layers"],
                "encryption_info": result["encryption_info"],
                "final_data": result["final_data"]
            }

            # Add layer-specific data if present
            if "layer_results" in result:
                cbor_data["layer_results"] = result["layer_results"]
            
            try:
                with open(vault_bin_file, "wb") as f:
                    cbor2.dump(cbor_data, f)
                # Set secure permissions on vault file
                set_secure_permissions(vault_bin_file)
                vault_info["files_created"].append(vault_bin_file)
            except Exception as e:
                raise IOError(f"Failed to create vault file: {e}")
            # Add steganography if enabled
            if self.config.has_layer(SecurityLayer.STEGANOGRAPHY) and images:
                stego_file = f"{output_dir}/stego_images/vault.bin.png"
                if self.stego.embed_data(vault_bin_file, images[0], stego_file):
                    vault_info["files_created"].append(stego_file)
        
        # All configuration is embedded in the vault.bin CBOR file
        return vault_info

    @staticmethod
    def recover_vault(vault_dir: str, passphrase: str) -> str:
        """
        Recover the original seed phrase from a vault directory using the provided passphrase.
        Supports modular layered encryption with standard_encryption, quantum_encryption, and combinations.
        """
        if not vault_dir or not os.path.exists(vault_dir):
            raise FileNotFoundError(f"Vault directory not found: {vault_dir}")

        vault_bin_path = os.path.join(vault_dir, "vault.bin")
        if not os.path.exists(vault_bin_path):
            raise FileNotFoundError(f"vault.bin not found in {vault_dir}")

        try:
            with open(vault_bin_path, "rb") as f:
                cbor_data = cbor2.load(f)
        except Exception as e:
            raise ValueError(f"Failed to read vault data: {e}")

        layers = cbor_data.get("layers", [])
        if not layers:
            # No layers - check if we have final_data to return
            if "final_data" in cbor_data:
                return base64.b64decode(cbor_data["final_data"]).decode()
            else:
                raise ValueError("No encrypted data found in vault")

        try:
            # Check if we have layered encryption data
            if "layer_results" in cbor_data and "final_data" in cbor_data:
                # New layered encryption format
                layered_enc = LayeredEncryption.create_from_vault_data(cbor_data, passphrase)
                decrypted_data = layered_enc.decrypt(cbor_data)
                return decrypted_data.decode()
            
            # Handle legacy single layer formats for backward compatibility
            elif layers == ["standard_encryption"]:
                # Legacy standard encryption format
                enc = cbor_data["standard_encryption"]
                salt = base64.b64decode(enc["salt"])

                # Extract Argon2id parameters
                memory_cost = int(enc.get("memory_cost", 524288))
                time_cost = int(enc.get("time_cost", 5))
                parallelism = int(enc.get("parallelism", 1))

                se = StandardEncryption(
                    passphrase,
                    salt=salt,
                    memory_cost=memory_cost,
                    time_cost=time_cost,
                    parallelism=parallelism,
                )

                return se.decrypt(enc).decode()
            
            elif layers == ["quantum_encryption"]:
                # Legacy quantum encryption format
                enc = cbor_data["quantum_encryption"]

                # Extract Argon2id parameters
                memory_cost = int(enc.get("memory_cost", 1048576))  # 1GB default
                time_cost = int(enc.get("time_cost", 5))
                parallelism = int(enc.get("parallelism", 1))

                # Initialize quantum encryption
                qe = QuantumEncryption(
                    passphrase=passphrase,
                    memory_cost=memory_cost,
                    time_cost=time_cost,
                    parallelism=parallelism,
                )

                # Decrypt with quantum encryption
                decrypted_data = qe.decrypt(enc)
                return decrypted_data.decode()
            
            elif not layers:
                # No encryption layers - just return the data
                if "final_data" in cbor_data:
                    return base64.b64decode(cbor_data["final_data"]).decode()
                else:
                    raise ValueError("No encrypted data found in vault")
            
            else:
                raise NotImplementedError(
                    f"Recovery for layers {layers} is not yet implemented. "
                    f"Please use the new layered encryption format."
                )
                
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
