"""
Integration tests for the complete vault functionality.
"""

import os
import cbor2
from src.core import QuantumSecretVault, SecurityConfig, SecurityLayer

class TestVaultIntegration:
    """Test suite for complete vault integration."""
    
    def test_vault_aes_only(self, temp_dir, sample_seed, sample_passphrase):
        """Test vault with AES encryption only."""
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION],
            passphrase=sample_passphrase,
            salt=os.urandom(32)
        )
        
        vault = QuantumSecretVault(config)
        result = vault.create_vault(sample_seed, temp_dir)
        
        # Verify result structure
        assert result["vault_created"] is True
        assert SecurityLayer.STANDARD_ENCRYPTION.value in result["layers"]
        assert len(result["files_created"]) == 1  # Only vault.bin for standard encryption
        
        # Check vault.bin file exists
        vault_file = os.path.join(temp_dir, "vault.bin")
        assert os.path.exists(vault_file)
        
        # Verify CBOR file structure
        with open(vault_file, 'rb') as f:
            cbor_data = cbor2.load(f)
        
        assert "layers" in cbor_data
        assert "encryption_info" in cbor_data
        assert "standard_encryption" in cbor_data["encryption_info"]
        assert cbor_data["layers"] == ["standard_encryption"]
        
        # Verify encryption metadata
        enc_data = cbor_data["encryption_info"]["standard_encryption"]
        assert "encryption_type" in enc_data
        assert "kdf" in enc_data
        assert "memory_cost" in enc_data
        assert "time_cost" in enc_data
        assert "parallelism" in enc_data
        assert enc_data["encryption_type"] == "AES-256-GCM"
        assert enc_data["kdf"] == "Argon2id"
    
    def test_vault_no_config_file_for_standard_encryption(self, temp_dir, sample_seed, sample_passphrase):
        """Test that no vault configuration file is created for standard encryption only."""
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION],
            passphrase=sample_passphrase,
            salt=os.urandom(32)
        )
        
        vault = QuantumSecretVault(config)
        result = vault.create_vault(sample_seed, temp_dir)
        
        # Check that no config file is created for standard encryption only
        config_file = os.path.join(temp_dir, "vault_config.json")
        assert not os.path.exists(config_file)
        
        # Only vault.bin should exist
        assert len(result["files_created"]) == 1
        assert result["files_created"][0].endswith("vault.bin")
    
    # def test_vault_steganography(self, temp_dir, sample_seed, sample_passphrase, sample_images):
    #     """Test vault with steganography."""
    #     config = SecurityConfig(
    #         layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.STEGANOGRAPHY],
    #         passphrase=sample_passphrase,
    #         salt=os.urandom(32)
    #     )
    #     
    #     vault = QuantumSecretVault(config)
    #     result = vault.create_vault(sample_seed, temp_dir, sample_images[:1])
    #     
    #     # Verify result structure
    #     assert result["vault_created"] is True
    #     assert SecurityLayer.STANDARD_ENCRYPTION.value in result["layers_used"]
    #     assert SecurityLayer.STEGANOGRAPHY.value in result["layers_used"]
    #     
    #     # Check stego images directory
    #     stego_dir = os.path.join(temp_dir, "stego_images")
    #     assert os.path.exists(stego_dir)
    #     
    #     # Should have at least one stego file
    #     stego_files = [f for f in os.listdir(stego_dir) if f.endswith('.png')]
    #     assert len(stego_files) >= 1
    
    # def test_vault_aes_and_stego(self, temp_dir, sample_seed, sample_passphrase, sample_images):
    #     """Test vault with AES encryption and steganography."""
    #     config = SecurityConfig(
    #         layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.STEGANOGRAPHY],
    #         passphrase=sample_passphrase,
    #         salt=os.urandom(32)
    #     )
    #     
    #     vault = QuantumSecretVault(config)
    #     result = vault.create_vault(sample_seed, temp_dir, sample_images[:1])
    #     
    #     # Verify result structure
    #     assert result["vault_created"] is True
    #     assert SecurityLayer.STANDARD_ENCRYPTION.value in result["layers_used"]
    #     assert SecurityLayer.STEGANOGRAPHY.value in result["layers_used"]
    #     
    #     # Should have stego images
    #     stego_dir = os.path.join(temp_dir, "stego_images")
    #     assert os.path.exists(stego_dir)
    #     
    #     # Should have at least one stego file
    #     stego_files = [f for f in os.listdir(stego_dir) if f.endswith('.png')]
    #     assert len(stego_files) >= 1
    
    def test_vault_file_permissions(self, temp_dir, sample_seed, sample_passphrase):
        """Test that vault files have appropriate permissions."""
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION],
            passphrase=sample_passphrase,
            salt=os.urandom(32)
        )
        
        vault = QuantumSecretVault(config)
        result = vault.create_vault(sample_seed, temp_dir)
        
        # Check that vault.bin file exists and is readable
        vault_file = os.path.join(temp_dir, "vault.bin")
        assert os.path.exists(vault_file)
        assert os.access(vault_file, os.R_OK)
        
        # Check secure permissions (600 - owner read/write only)
        file_stat = os.stat(vault_file)
        file_mode = file_stat.st_mode & 0o777
        assert file_mode == 0o600  # Should be readable/writable by owner only
    
    def test_vault_recovery_roundtrip(self, temp_dir, sample_seed, sample_passphrase):
        """Test that vault can be created and recovered successfully."""
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION],
            passphrase=sample_passphrase,
            salt=os.urandom(32)
        )
        
        # Create vault
        vault = QuantumSecretVault(config)
        result = vault.create_vault(sample_seed, temp_dir)
        
        assert result["vault_created"] is True
        assert len(result["files_created"]) == 1
        
        # Recover vault
        recovered_seed = QuantumSecretVault.recover_vault(temp_dir, sample_passphrase)
        
        # Verify recovery
        assert recovered_seed == sample_seed 