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
    
    def test_vault_shamir_only(self, temp_dir, sample_seed, sample_passphrase):
        """Test vault with Shamir sharing only."""
        config = SecurityConfig(
            layers=[SecurityLayer.SHAMIR_SHARING],
            shamir_threshold=3,
            shamir_total=5,
            parity_shares=1,
            passphrase=sample_passphrase,
            salt=os.urandom(32)
        )
        
        vault = QuantumSecretVault(config)
        result = vault.create_vault(sample_seed, temp_dir)
        
        # Verify result structure
        assert result["vault_created"] is True
        assert SecurityLayer.SHAMIR_SHARING.value in result["layers_used"]
        
        # Should have 6 share files (5 + 1 parity) + config file
        assert len(result["files_created"]) == 7
        
        # Check shares directory exists
        shares_dir = os.path.join(temp_dir, "shares")
        assert os.path.exists(shares_dir)
        
        # Check share files
        share_files = [f for f in os.listdir(shares_dir) if f.endswith('.json')]
        assert len(share_files) == 6
        
        # Verify share file structure
        share_file = os.path.join(shares_dir, "share_0.json")
        with open(share_file, 'r') as f:
            data = json.load(f)
        
        assert "share_id" in data
        assert "share_type" in data
        assert "data" in data
        assert data["share_id"] == 0
        assert data["share_type"] == "Shamir"
    
    def test_vault_aes_and_shamir(self, temp_dir, sample_seed, sample_passphrase):
        """Test vault with AES encryption and Shamir sharing."""
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.SHAMIR_SHARING],
            shamir_threshold=3,
            shamir_total=5,
            parity_shares=1,
            passphrase=sample_passphrase,
            salt=os.urandom(32)
        )
        
        vault = QuantumSecretVault(config)
        result = vault.create_vault(sample_seed, temp_dir)
        
        # Verify result structure
        assert result["vault_created"] is True
        assert SecurityLayer.STANDARD_ENCRYPTION.value in result["layers_used"]
        assert SecurityLayer.SHAMIR_SHARING.value in result["layers_used"]
        
        # Should have 6 share files + config file
        assert len(result["files_created"]) == 7
        
        # Verify encryption info in shares
        shares_dir = os.path.join(temp_dir, "shares")
        share_file = os.path.join(shares_dir, "share_0.json")
        
        with open(share_file, 'r') as f:
            data = json.load(f)
        
        assert "encryption_info" in data
        assert "standard_encryption" in data["encryption_info"]
    
    def test_vault_config_file(self, temp_dir, sample_seed, sample_passphrase):
        """Test vault configuration file generation."""
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.SHAMIR_SHARING],
            shamir_threshold=3,
            shamir_total=5,
            parity_shares=1,
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
        assert "shamir_config" in config_data
        assert "created_timestamp" in config_data
        
        # Verify layers
        assert SecurityLayer.STANDARD_ENCRYPTION.value in config_data["layers"]
        assert SecurityLayer.SHAMIR_SHARING.value in config_data["layers"]
        
        # Verify Shamir config
        shamir_config = config_data["shamir_config"]
        assert shamir_config["threshold"] == 3
        assert shamir_config["total"] == 5
        assert shamir_config["parity"] == 1
    
    def test_vault_steganography(self, temp_dir, sample_seed, sample_passphrase, sample_images):
        """Test vault with steganography."""
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.STEGANOGRAPHY],
            passphrase=sample_passphrase,
            salt=os.urandom(32)
        )
        
        vault = QuantumSecretVault(config)
        result = vault.create_vault(sample_seed, temp_dir, sample_images[:1])
        
        # Verify result structure
        assert result["vault_created"] is True
        assert SecurityLayer.STANDARD_ENCRYPTION.value in result["layers_used"]
        assert SecurityLayer.STEGANOGRAPHY.value in result["layers_used"]
        
        # Check stego images directory
        stego_dir = os.path.join(temp_dir, "stego_images")
        assert os.path.exists(stego_dir)
        
        # Should have at least one stego file
        stego_files = [f for f in os.listdir(stego_dir) if f.endswith('.png')]
        assert len(stego_files) >= 1
    
    def test_vault_all_layers(self, temp_dir, sample_seed, sample_passphrase, sample_images):
        """Test vault with all available layers."""
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.SHAMIR_SHARING, SecurityLayer.STEGANOGRAPHY],
            shamir_threshold=3,
            shamir_total=5,
            parity_shares=1,
            passphrase=sample_passphrase,
            salt=os.urandom(32)
        )
        
        vault = QuantumSecretVault(config)
        result = vault.create_vault(sample_seed, temp_dir, sample_images[:6])
        
        # Verify result structure
        assert result["vault_created"] is True
        assert SecurityLayer.STANDARD_ENCRYPTION.value in result["layers_used"]
        assert SecurityLayer.SHAMIR_SHARING.value in result["layers_used"]
        assert SecurityLayer.STEGANOGRAPHY.value in result["layers_used"]
        
        # Should have shares and stego images
        shares_dir = os.path.join(temp_dir, "shares")
        stego_dir = os.path.join(temp_dir, "stego_images")
        
        assert os.path.exists(shares_dir)
        assert os.path.exists(stego_dir)
        
        # Check file counts
        share_files = [f for f in os.listdir(shares_dir) if f.endswith('.json')]
        stego_files = [f for f in os.listdir(stego_dir) if f.endswith('.png')]
        
        assert len(share_files) == 6  # 5 + 1 parity
        assert len(stego_files) >= 1  # At least one stego image
    
    def test_vault_error_handling(self, temp_dir, sample_seed, sample_passphrase):
        """Test vault error handling."""
        # Test with invalid Shamir parameters
        config = SecurityConfig(
            layers=[SecurityLayer.SHAMIR_SHARING],
            shamir_threshold=5,
            shamir_total=3,  # Invalid: threshold > total
            passphrase=sample_passphrase,
            salt=os.urandom(32)
        )
        
        vault = QuantumSecretVault(config)
        
        # This should handle the error gracefully
        result = vault.create_vault(sample_seed, temp_dir)
        assert result["vault_created"] is True
    
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