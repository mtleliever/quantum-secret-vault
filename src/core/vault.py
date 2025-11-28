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

from .config import SecurityConfig, SecurityLayer
from .layered_encryption import LayeredEncryption
from ..utils.file_utils import (
    set_secure_permissions, 
    set_secure_directory_permissions,
    validate_path
)


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
            config.password,
            config.salt,
            config.argon2_memory_cost,
            config.argon2_time_cost,
            config.argon2_parallelism,
        )
        self.quantum_enc = QuantumEncryption(
            password=config.password,
            memory_cost=config.argon2_memory_cost,
            time_cost=config.argon2_time_cost,
            parallelism=config.argon2_parallelism,
        )
        self.shamir = ShamirSharing(
            config.shamir_threshold, config.shamir_total, config.parity_shares
        )


    def encrypt_secret(self, secret: str) -> Dict[str, Any]:
        """
        Encrypt secret using selected security layers in a modular, layered approach.
        All layers including Shamir sharing are handled by LayeredEncryption.

        Args:
            secret: Secret string to encrypt

        Returns:
            Dictionary with encrypted data/shares and metadata
        """
        # Apply layered encryption with all configured layers
        if self.config.layers:
            layered_enc = LayeredEncryption(
                password=self.config.password,
                layers=self.config.layers,
                memory_cost=self.config.argon2_memory_cost,
                time_cost=self.config.argon2_time_cost,
                parallelism=self.config.argon2_parallelism,
                shamir_threshold=self.config.shamir_threshold,
                shamir_total=self.config.shamir_total,
                parity_shares=self.config.parity_shares,
                salt=self.config.salt,
            )

            # Encrypt the secret through all layers
            return layered_enc.encrypt(secret.encode("utf-8"))
        else:
            # No layers - just encode the secret
            return {
                "layers": [],
                "ciphertext": base64.b64encode(secret.encode("utf-8")).decode("utf-8"),
            }

    def create_vault(
        self, secret: str, output_dir: str, allowed_base: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create the complete vault with all selected layers.

        Args:
            secret: Secret string to protect
            output_dir: Directory to create vault in
            allowed_base: Optional base directory for path validation.
                         If provided, output_dir must be within this directory.

        Returns:
            Dictionary with vault creation information
            
        Raises:
            PathTraversalError: If output_dir would escape allowed_base
            ValueError: If paths are invalid
        """
        # Validate and sanitize the output directory path
        validated_output_dir = validate_path(output_dir, allowed_base)
        
        os.makedirs(validated_output_dir, exist_ok=True)
        # Set secure permissions on output directory (cross-platform)
        set_secure_directory_permissions(validated_output_dir)

        # Create subdirectories based on layers
        if self.config.has_layer(SecurityLayer.SHAMIR_SHARING):
            shares_dir = os.path.join(validated_output_dir, "shares")
            os.makedirs(shares_dir, exist_ok=True)
            set_secure_directory_permissions(shares_dir)

        # Encrypt the secret
        result = self.encrypt_secret(secret)

        vault_info = {
            "vault_created": True,
            "layers": [layer_info["layer"] for layer_info in result["layers"]],
            "files_created": [],
        }

        # Add layer_results if available
        if "layers" in result:
            vault_info["layer_results"] = result["layers"]

        # Handle different output formats based on layers
        if self.config.has_layer(SecurityLayer.SHAMIR_SHARING):
            # Multiple shares
            shares = result["shares"]
            for i, share in enumerate(shares):
                share_file = os.path.join(validated_output_dir, "shares", f"share_{i}.bin")
                share_data = {
                    "share_id": i,
                    "share_type": "Shamir+Reed-Solomon",
                    "data": (
                        base64.b64encode(share).decode("utf-8")
                        if isinstance(share, bytes)
                        else share
                    ),
                    "layers": result["layers"],
                }
                with open(share_file, "wb") as f:
                    cbor2.dump(share_data, f)
                set_secure_permissions(share_file)
                vault_info["files_created"].append(share_file)


        else:
            # Single encrypted file (CBOR binary)
            vault_bin_file = os.path.join(validated_output_dir, "vault.bin")
            cbor_data = {"layers": result["layers"], "ciphertext": result["ciphertext"]}

            # No need to add layer-specific data separately since it's already in layers

            try:
                with open(vault_bin_file, "wb") as f:
                    cbor2.dump(cbor_data, f)
                # Set secure permissions on vault file
                set_secure_permissions(vault_bin_file)
                vault_info["files_created"].append(vault_bin_file)
            except Exception as e:
                raise IOError(f"Failed to create vault file: {e}")


        # All configuration is embedded in the vault.bin CBOR file
        return vault_info

    @staticmethod
    def inspect_vault(vault_dir: str, allowed_base: Optional[str] = None) -> Dict[str, Any]:
        """
        Inspect vault contents and return detailed information about layers and parameters.
        Supports both single vault.bin files and Shamir share files.
        
        Args:
            vault_dir: Directory containing vault.bin or shares/
            allowed_base: Optional base directory for path validation
            
        Returns:
            Dictionary with comprehensive vault information
            
        Raises:
            PathTraversalError: If vault_dir would escape allowed_base
            FileNotFoundError: If vault directory doesn't exist
        """
        # Validate path to prevent directory traversal attacks
        validated_vault_dir = validate_path(vault_dir, allowed_base)
        
        if not os.path.exists(validated_vault_dir):
            raise FileNotFoundError(f"Vault directory not found: {vault_dir}")

        vault_bin_path = os.path.join(validated_vault_dir, "vault.bin")
        shares_path = os.path.join(validated_vault_dir, "shares")
        
        cbor_data = None
        vault_type = "unknown"
        
        # Try single vault.bin first
        if os.path.exists(vault_bin_path):
            try:
                with open(vault_bin_path, "rb") as f:
                    cbor_data = cbor2.load(f)
                vault_type = "single_vault"
            except Exception as e:
                raise ValueError(f"Failed to read vault.bin: {e}")
        
        # Try Shamir shares if vault.bin doesn't exist
        elif os.path.exists(shares_path):
            share_files = [f for f in os.listdir(shares_path) if f.startswith("share_") and f.endswith(".bin")]
            if not share_files:
                raise FileNotFoundError(f"No share files found in {shares_path}")
            
            # Load the first share to get layer information
            first_share_path = os.path.join(shares_path, share_files[0])
            try:
                with open(first_share_path, "rb") as f:
                    share_data = cbor2.load(f)
                
                # Reconstruct cbor_data format from share data
                cbor_data = {
                    "layers": share_data["layers"],
                    "shares": [f"Share data from {len(share_files)} files"],  # Placeholder
                    "share_info": {
                        "total_shares": len(share_files),
                        "share_type": share_data.get("share_type", "Shamir"),
                        "first_share_id": share_data.get("share_id", 0)
                    }
                }
                vault_type = "shamir_shares"
            except Exception as e:
                raise ValueError(f"Failed to read share file {first_share_path}: {e}")
        
        else:
            raise FileNotFoundError(f"Neither vault.bin nor shares/ directory found in {vault_dir}")

        if cbor_data is None:
            raise ValueError("Unable to load vault data from any source")

        # Convert bytes to base64 for display
        def make_displayable(obj):
            if isinstance(obj, bytes):
                return {
                    "type": "bytes",
                    "length": len(obj),
                    "base64": base64.b64encode(obj).decode('utf-8')[:100] + "..." if len(obj) > 50 else base64.b64encode(obj).decode('utf-8')
                }
            elif isinstance(obj, dict):
                return {k: make_displayable(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [make_displayable(item) for item in obj]
            else:
                return obj

        # Build vault info based on vault type
        if vault_type == "single_vault":
            vault_info = {
                "vault_type": "Single Vault File",
                "vault_structure": make_displayable(cbor_data),
                "layers_summary": [],
                "data_size": len(cbor_data.get("ciphertext", b"")),
                "has_ciphertext": "ciphertext" in cbor_data,
                "total_layers": len(cbor_data.get("layers", [])),
            }
        else:  # shamir_shares
            share_info = cbor_data.get("share_info", {})
            vault_info = {
                "vault_type": "Shamir Secret Sharing",
                "vault_structure": make_displayable(cbor_data),
                "layers_summary": [],
                "total_shares": share_info.get("total_shares", 0),
                "share_type": share_info.get("share_type", "Unknown"),
                "has_shares": "shares" in cbor_data,
                "total_layers": len(cbor_data.get("layers", [])),
            }

        # Analyze each layer
        for i, layer_info in enumerate(cbor_data.get("layers", [])):
            layer_summary = {
                "layer_index": i,
                "layer_type": layer_info.get("layer", "unknown"),
                "metadata_keys": list(layer_info.get("metadata", {}).keys()),
                "metadata_details": {}
            }
            
            metadata = layer_info.get("metadata", {})
            if "kdf" in metadata:
                layer_summary["metadata_details"]["kdf"] = metadata["kdf"]
            if "memory_cost" in metadata:
                layer_summary["metadata_details"]["memory_cost"] = metadata["memory_cost"]
            if "time_cost" in metadata:
                layer_summary["metadata_details"]["time_cost"] = metadata["time_cost"]
            if "parallelism" in metadata:
                layer_summary["metadata_details"]["parallelism"] = metadata["parallelism"]
            if "encryption_type" in metadata:
                layer_summary["metadata_details"]["encryption_type"] = metadata["encryption_type"]
            if "salt" in metadata:
                layer_summary["metadata_details"]["salt_length"] = len(base64.b64decode(metadata["salt"]))
            if "kyber_public_key" in metadata:
                layer_summary["metadata_details"]["kyber_public_key_length"] = len(metadata["kyber_public_key"])
            if "kyber_ciphertext" in metadata:
                layer_summary["metadata_details"]["kyber_ciphertext_length"] = len(metadata["kyber_ciphertext"])
            if "encrypted_private_key" in metadata:
                layer_summary["metadata_details"]["encrypted_private_key_length"] = len(metadata["encrypted_private_key"])
            
            # Shamir-specific metadata
            if "threshold" in metadata:
                layer_summary["metadata_details"]["threshold"] = metadata["threshold"]
            if "total" in metadata:
                layer_summary["metadata_details"]["total"] = metadata["total"]
            if "parity" in metadata:
                layer_summary["metadata_details"]["parity"] = metadata["parity"]
            
            vault_info["layers_summary"].append(layer_summary)

        return vault_info

    @staticmethod
    def recover_vault(vault_dir: str, password: str, show_details: bool = False,
                      allowed_base: Optional[str] = None) -> str:
        """
        Recover the original secret from a vault directory using the provided password.
        Supports modular layered encryption with standard_encryption, quantum_encryption, and combinations.
        
        Args:
            vault_dir: Directory containing vault.bin
            password: Password for decryption
            show_details: If True, print detailed vault information before recovery
            allowed_base: Optional base directory for path validation
            
        Returns:
            Decrypted secret
            
        Raises:
            PathTraversalError: If vault_dir would escape allowed_base
            FileNotFoundError: If vault directory doesn't exist
            ValueError: If decryption fails (generic message to prevent information leakage)
        """
        # Validate path to prevent directory traversal attacks
        validated_vault_dir = validate_path(vault_dir, allowed_base)
        
        if show_details:
            print("=== VAULT INSPECTION ===")
            try:
                vault_info = QuantumSecretVault.inspect_vault(validated_vault_dir)
                print(f"Vault type: {vault_info['vault_type']}")
                print(f"Total layers: {vault_info['total_layers']}")
                
                # Show different info based on vault type
                if vault_info['vault_type'] == "Single Vault File":
                    print(f"Data size: {vault_info['data_size']} bytes")
                    print(f"Has ciphertext: {vault_info['has_ciphertext']}")
                else:  # Shamir shares
                    print(f"Total shares: {vault_info['total_shares']}")
                    print(f"Share type: {vault_info['share_type']}")
                    print(f"Has shares: {vault_info['has_shares']}")
                
                print()
                
                for layer_summary in vault_info['layers_summary']:
                    print(f"Layer {layer_summary['layer_index']}: {layer_summary['layer_type']}")
                    for key, value in layer_summary['metadata_details'].items():
                        print(f"  {key}: {value}")
                    print()
                
                print("=== COMPLETE VAULT STRUCTURE (JSON) ===")
                print(json.dumps(vault_info['vault_structure'], indent=2))
                print()
                    
            except Exception as e:
                print(f"Error inspecting vault: {e}")
            print("=== STARTING RECOVERY ===")
            print()

        if not os.path.exists(validated_vault_dir):
            raise FileNotFoundError(f"Vault directory not found: {vault_dir}")

        vault_bin_path = os.path.join(validated_vault_dir, "vault.bin")
        shares_path = os.path.join(validated_vault_dir, "shares")
        
        # Auto-detect vault type
        if os.path.exists(vault_bin_path):
            # Standard vault with vault.bin file - continue with existing logic
            pass
        elif os.path.exists(shares_path) or any(f.startswith("share_") and f.endswith(".bin") for f in os.listdir(validated_vault_dir)):
            # Shamir shares vault - load shares and reconstruct vault data
            return QuantumSecretVault._recover_from_shares(validated_vault_dir, password, show_details=show_details)
        else:
            raise FileNotFoundError(f"No vault.bin or share files found in {validated_vault_dir}")

        try:
            with open(vault_bin_path, "rb") as f:
                cbor_data = cbor2.load(f)
        except Exception as e:
            raise ValueError(f"Failed to read vault data: {e}")

        layers = cbor_data.get("layers", [])
        if not layers:
            # No layers - check if we have ciphertext to return
            if "ciphertext" in cbor_data:
                return base64.b64decode(cbor_data["ciphertext"]).decode()
            else:
                raise ValueError("No encrypted data found in vault")

        try:
            # Check if we have layered encryption data
            if "layers" in cbor_data and ("ciphertext" in cbor_data):
                # New layered encryption format
                layered_enc = LayeredEncryption.create_from_vault_data(
                    cbor_data, password
                )
                decrypted_data = layered_enc.decrypt(cbor_data)
                return decrypted_data.decode()
            
            # Handle legacy single layer formats for backward compatibility
            elif isinstance(layers, list) and len(layers) == 1 and isinstance(layers[0], str):
                # Legacy format where layers was a simple string array
                layer_type = layers[0]
                
                if layer_type == "standard_encryption":
                    # Legacy standard encryption format
                    enc = cbor_data["standard_encryption"]
                    salt = base64.b64decode(enc["salt"])

                    # Extract Argon2id parameters
                    memory_cost = int(enc.get("memory_cost", 524288))
                    time_cost = int(enc.get("time_cost", 5))
                    parallelism = int(enc.get("parallelism", 1))

                    se = StandardEncryption(
                        password,
                        salt=salt,
                        memory_cost=memory_cost,
                        time_cost=time_cost,
                        parallelism=parallelism,
                    )

                    return se.decrypt(enc).decode()
                
                elif layer_type == "quantum_encryption":
                    # Legacy quantum encryption format
                    enc = cbor_data["quantum_encryption"]

                    # Extract Argon2id parameters
                    memory_cost = int(enc.get("memory_cost", 1048576))  # 1GB default
                    time_cost = int(enc.get("time_cost", 5))
                    parallelism = int(enc.get("parallelism", 1))

                    # Initialize quantum encryption
                    qe = QuantumEncryption(
                        password=password,
                        memory_cost=memory_cost,
                        time_cost=time_cost,
                        parallelism=parallelism,
                    )

                    # Decrypt with quantum encryption
                    decrypted_data = qe.decrypt(enc)
                    return decrypted_data.decode()
                
                else:
                    raise NotImplementedError(
                        f"Recovery for layer {layer_type} is not yet implemented. "
                        f"Please use the new layered encryption format."
                    )
            
            else:
                raise NotImplementedError(
                    f"Recovery for this vault format is not yet implemented. "
                    f"Please use the new layered encryption format."
                )
                
        except (NotImplementedError, FileNotFoundError):
            # Re-raise these specific exceptions as-is
            raise
        except Exception:
            # Generic error message to prevent information leakage
            raise ValueError("Decryption failed: invalid password or corrupted data")

    @staticmethod
    def _recover_from_shares(vault_dir: str, password: str, show_details: bool = False) -> str:
        """
        Recover from Shamir share files using integrated LayeredEncryption.
        
        Args:
            vault_dir: Directory containing share files
            password: Password for decryption
            show_details: If True, print detailed recovery information
            
        Returns:
            Decrypted secret
        """
        # Find share files
        shares_path = os.path.join(vault_dir, "shares")
        if os.path.exists(shares_path):
            share_files = [f for f in os.listdir(shares_path) if f.startswith("share_") and f.endswith(".bin")]
            share_files = [os.path.join(shares_path, f) for f in share_files]
        else:
            share_files = [os.path.join(vault_dir, f) for f in os.listdir(vault_dir) if f.startswith("share_") and f.endswith(".bin")]
        
        if not share_files:
            raise FileNotFoundError(f"No share files found in {vault_dir}")
        
        # Load share data
        shares_data = []
        layer_info = None
        
        for share_file in sorted(share_files):
            try:
                with open(share_file, 'rb') as f:
                    share_data = cbor2.load(f)
                shares_data.append(share_data)
                
                # Extract layer info from first share
                if layer_info is None:
                    layer_info = share_data.get("layers", [])
                    
            except Exception as e:
                if show_details:
                    print(f"Warning: Failed to load share file {share_file}: {e}")
                continue
        
        if not shares_data:
            raise ValueError("No valid share files could be loaded")
        
        if show_details:
            print(f"Found {len(shares_data)} share files")
            if layer_info:
                print(f"Layers detected: {[layer.get('layer', 'unknown') for layer in layer_info]}")
        
        # Extract raw shares (bytes) - decode from base64 if needed
        raw_shares = []
        for share_data in shares_data:
            if isinstance(share_data["data"], str):
                # Data is base64 encoded string, decode it back to bytes
                try:
                    share_bytes = base64.b64decode(share_data["data"])
                except Exception:
                    # Fallback: if not base64, treat as UTF-8 string
                    share_bytes = share_data["data"].encode('utf-8')
            else:
                share_bytes = share_data["data"]
            raw_shares.append(share_bytes)
        
        # Reconstruct vault data structure with shares
        vault_data = {
            "layers": layer_info,
            "shares": raw_shares
        }
        
        # Use LayeredEncryption to decrypt (handles Shamir reconstruction internally)
        if layer_info:
            try:
                layered_enc = LayeredEncryption.create_from_vault_data(vault_data, password)
                decrypted_data = layered_enc.decrypt(vault_data)
                return decrypted_data.decode()
            except Exception:
                # Generic error message to prevent information leakage
                raise ValueError("Decryption failed: invalid password or corrupted data")
        else:
            # No encryption layers - shouldn't happen with Shamir but handle gracefully
            raise ValueError("No encryption layers found in share data")
