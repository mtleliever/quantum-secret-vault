"""
Integration tests for the complete vault functionality.
"""

import pytest
import os
import json
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
        assert SecurityLayer.STANDARD_ENCRYPTION.value in result["layers_used"]
        assert len(result["files_created"]) >= 2  # encrypted_seed.json + vault_config.json
        
        # Check encrypted file exists
        encrypted_file = os.path.join(temp_dir, "encrypted_seed.json")
        assert os.path.exists(encrypted_file)
        
        # Verify file structure
        with open(encrypted_file, 'r') as f:
            data = json.load(f)
        
        assert "encrypted_data" in data
        assert "encryption_info" in data
        assert "standard_encryption" in data["encryption_info"]
    
    def test_vault_config_file(self, temp_dir, sample_seed, sample_passphrase):
        """Test vault configuration file generation."""
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION],
            passphrase=sample_passphrase,
            salt=os.urandom(32)
        )
        
        vault = QuantumSecretVault(config)
        result = vault.create_vault(sample_seed, temp_dir)
        
        # Check config file
        config_file = os.path.join(temp_dir, "vault_config.json")
        assert os.path.exists(config_file)
        
        with open(config_file, 'r') as f:
            config_data = json.load(f)
        
        assert "layers" in config_data
        assert "created_timestamp" in config_data
        
        # Verify layers
        assert SecurityLayer.STANDARD_ENCRYPTION.value in config_data["layers"]
    
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
        
        # Check that files are readable
        encrypted_file = os.path.join(temp_dir, "encrypted_seed.json")
        config_file = os.path.join(temp_dir, "vault_config.json")
        
        assert os.access(encrypted_file, os.R_OK)
        assert os.access(config_file, os.R_OK) 