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
        Encrypt seed using selected security layers.

        Args:
            seed: Seed string to encrypt

        Returns:
            Dictionary with encrypted data and metadata
        """
        current_data = seed.encode("utf-8")
        encryption_info = {}

        # Layer 1: Standard Encryption (if enabled)
        if self.config.has_layer(SecurityLayer.STANDARD_ENCRYPTION):
            encrypted = self.standard_enc.encrypt(current_data)
            current_data = json.dumps(encrypted).encode("utf-8")
            encryption_info["standard_encryption"] = {
                "salt": encrypted["salt"],
                "kdf": encrypted["kdf"],
                "memory_cost": encrypted["memory_cost"],
                "time_cost": encrypted["time_cost"],
                "parallelism": encrypted["parallelism"],
            }

        # Layer 2: Quantum Encryption (if enabled)
        if self.config.has_layer(SecurityLayer.QUANTUM_ENCRYPTION):
            encrypted = self.quantum_enc.encrypt(current_data)
            current_data = json.dumps(encrypted).encode("utf-8")
            encryption_info["quantum_encryption"] = {
                "algorithm": encrypted["encryption_type"],
                "memory_cost": encrypted["memory_cost"],
                "time_cost": encrypted["time_cost"],
                "parallelism": encrypted["parallelism"],
                "key_commitment": True,
                "hmac_combination": True,
            }

        # Layer 3: Shamir Secret Sharing (if enabled)
        if self.config.has_layer(SecurityLayer.SHAMIR_SHARING):
            shares = self.shamir.split_secret(current_data.decode("utf-8"))
            encryption_info["shamir_sharing"] = {
                "threshold": self.config.shamir_threshold,
                "total": self.config.shamir_total,
                "parity": self.config.parity_shares,
                "shares_count": len(shares),
            }
            return {
                "shares": shares,
                "encryption_info": encryption_info,
                "layers_used": [layer.value for layer in self.config.layers],
            }
        else:
            # No sharing, return single encrypted data
            return {
                "encrypted_data": current_data.decode("utf-8"),
                "encryption_info": encryption_info,
                "layers_used": [layer.value for layer in self.config.layers],
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
            "layers_used": result["layers_used"],
            "encryption_info": result["encryption_info"],
            "files_created": [],
        }

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
                "layers": [layer.value for layer in self.config.layers],
                "encryption_info": result["encryption_info"],
            }

            # Add layer-specific data
            if self.config.has_layer(SecurityLayer.STANDARD_ENCRYPTION):
                cbor_data["standard_encryption"] = json.loads(result["encrypted_data"])
            elif self.config.has_layer(SecurityLayer.QUANTUM_ENCRYPTION):
                cbor_data["quantum_encryption"] = json.loads(result["encrypted_data"])
            else:
                # Just raw data if no encryption layers
                cbor_data["raw_data"] = result["encrypted_data"]
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
        Supports standard_encryption, quantum_encryption, and combined layers.
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
            raise ValueError("No layers found in vault.bin")

        # Support standard_encryption
        if layers == ["standard_encryption"]:
            try:
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
            except Exception as e:
                raise ValueError(f"Standard decryption failed: {e}")

        # Support quantum_encryption
        elif layers == ["quantum_encryption"]:
            try:
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
            except Exception as e:
                raise ValueError(f"Quantum decryption failed: {e}")

        # Support combined layers
        elif "standard_encryption" in layers and "quantum_encryption" in layers:
            try:
                # First decrypt quantum layer
                qe_enc = cbor_data["quantum_encryption"]
                memory_cost = int(qe_enc.get("memory_cost", 1048576))
                time_cost = int(qe_enc.get("time_cost", 5))
                parallelism = int(qe_enc.get("parallelism", 1))

                qe = QuantumEncryption(
                    passphrase=passphrase,
                    memory_cost=memory_cost,
                    time_cost=time_cost,
                    parallelism=parallelism,
                )

                decrypted_quantum = qe.decrypt(qe_enc)

                # Then decrypt standard layer
                standard_data = json.loads(decrypted_quantum.decode())
                salt = base64.b64decode(standard_data["salt"])

                se_memory_cost = int(standard_data.get("memory_cost", 524288))
                se_time_cost = int(standard_data.get("time_cost", 5))
                se_parallelism = int(standard_data.get("parallelism", 1))

                se = StandardEncryption(
                    passphrase,
                    salt=salt,
                    memory_cost=se_memory_cost,
                    time_cost=se_time_cost,
                    parallelism=se_parallelism,
                )

                return se.decrypt(standard_data).decode()
            except Exception as e:
                raise ValueError(f"Combined layer decryption failed: {e}")

        # TODO: Add support for Shamir, steganography, etc.
        raise NotImplementedError(
            f"Recovery for layers {layers} is not yet implemented."
        )
