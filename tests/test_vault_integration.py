"""
Integration tests for the quantum secret vault with different layer combinations.
"""

import os
import tempfile 
import shutil
import pytest
from src.core import QuantumSecretVault, SecurityConfig, SecurityLayer


class TestVaultIntegration:
    """Test suite for vault integration with various security layers."""
    
    def test_shamir_sharing_integration(self):
        """Test complete Shamir sharing workflow with layered encryption."""
        seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        passphrase = "test_passphrase_123"
        
        # Create temporary directory for vault
        with tempfile.TemporaryDirectory() as temp_dir:
            # Configure vault with standard encryption + Shamir sharing
            config = SecurityConfig(
                layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.SHAMIR_SHARING],
                shamir_threshold=3,
                shamir_total=5,
                parity_shares=2,
                passphrase=passphrase,
                salt=os.urandom(32),
                argon2_memory_cost=65536,  # Lower for test speed
                argon2_time_cost=3,
                argon2_parallelism=1
            )
            
            # Create vault
            vault = QuantumSecretVault(config)
            result = vault.create_vault(seed, temp_dir)
            
            # Verify vault creation
            assert result["vault_created"] is True
            assert "standard_encryption" in result["layers"]
            assert len(result["files_created"]) == 7  # 5 shares + 2 parity shares
            
            # Verify share files exist
            shares_dir = os.path.join(temp_dir, "shares")
            assert os.path.exists(shares_dir)
            
            share_files = [f for f in os.listdir(shares_dir) if f.startswith("share_")]
            assert len(share_files) == 7  # 5 + 2 parity
            
            # Test recovery using the general recover_vault method (auto-detection)  
            recovered_seed = QuantumSecretVault.recover_vault(
                temp_dir, passphrase, show_details=True
            )
            
            assert recovered_seed == seed
    
    def test_shamir_with_quantum_encryption(self):
        """Test Shamir sharing with quantum encryption layer."""
        seed = "test seed phrase for quantum shamir integration"
        passphrase = "quantum_test_pass"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Configure vault with both quantum encryption and Shamir sharing
            config = SecurityConfig(
                layers=[SecurityLayer.QUANTUM_ENCRYPTION, SecurityLayer.SHAMIR_SHARING],
                shamir_threshold=2,
                shamir_total=3,
                parity_shares=1,
                passphrase=passphrase,
                salt=os.urandom(32),
                argon2_memory_cost=65536,
                argon2_time_cost=3,
                argon2_parallelism=1
            )
            
            # Create vault
            vault = QuantumSecretVault(config)
            result = vault.create_vault(seed, temp_dir)
            
            # Verify creation
            assert result["vault_created"] is True
            assert "quantum_encryption" in result["layers"]
            assert len(result["files_created"]) == 4  # 3 shares + 1 parity
            
            # Test recovery
            recovered_seed = QuantumSecretVault.recover_vault(
                temp_dir, passphrase
            )
            
            assert recovered_seed == seed
    
    def test_shamir_with_layered_encryption(self):
        """Test Shamir sharing with both standard and quantum encryption."""
        seed = "multi layer encryption test seed phrase here"
        passphrase = "multi_layer_pass"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Configure vault with multiple encryption layers + Shamir
            config = SecurityConfig(
                layers=[
                    SecurityLayer.STANDARD_ENCRYPTION,
                    SecurityLayer.QUANTUM_ENCRYPTION, 
                    SecurityLayer.SHAMIR_SHARING
                ],
                shamir_threshold=4,
                shamir_total=6,
                parity_shares=2,
                passphrase=passphrase,
                salt=os.urandom(32),
                argon2_memory_cost=65536,
                argon2_time_cost=3,
                argon2_parallelism=1
            )
            
            # Create vault
            vault = QuantumSecretVault(config)
            result = vault.create_vault(seed, temp_dir)
            
            # Verify creation
            assert result["vault_created"] is True
            assert "standard_encryption" in result["layers"]
            assert "quantum_encryption" in result["layers"]
            assert len(result["files_created"]) == 8  # 6 shares + 2 parity
            
            # Test recovery with exactly threshold shares
            recovered_seed = QuantumSecretVault.recover_vault(
                temp_dir, passphrase
            )
            
            assert recovered_seed == seed
            
            # Test recovery with more than threshold shares  
            recovered_seed = QuantumSecretVault.recover_vault(
                temp_dir, passphrase
            )
            
            assert recovered_seed == seed
    
    def test_shamir_only_no_encryption(self):
        """Test Shamir sharing without any encryption layers."""
        seed = "plain shamir test without encryption layers"
        passphrase = "not_used_for_encryption"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Configure vault with only Shamir sharing
            config = SecurityConfig(
                layers=[SecurityLayer.SHAMIR_SHARING],
                shamir_threshold=2,
                shamir_total=4,
                parity_shares=1,
                passphrase=passphrase,
                salt=os.urandom(32)
            )
            
            # Create vault
            vault = QuantumSecretVault(config)
            result = vault.create_vault(seed, temp_dir)
            
            # Verify creation
            assert result["vault_created"] is True
            assert len(result["layers"]) == 1  # Just Shamir layer (no encryption layers)
            assert result["layers"][0] == "shamir_sharing"
            assert len(result["files_created"]) == 5  # 4 shares + 1 parity
            
            # Test recovery
            recovered_seed = QuantumSecretVault.recover_vault(
                temp_dir, passphrase
            )
            
            assert recovered_seed == seed
    
    def test_insufficient_shares_error(self):
        """Test that recovery fails with insufficient shares."""
        seed = "test insufficient shares error handling"
        passphrase = "test_pass"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            config = SecurityConfig(
                layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.SHAMIR_SHARING],
                shamir_threshold=4,
                shamir_total=5,
                parity_shares=1,
                passphrase=passphrase,
                salt=os.urandom(32),
                argon2_memory_cost=65536,
                argon2_time_cost=3,
                argon2_parallelism=1
            )
            
            # Create vault
            vault = QuantumSecretVault(config)
            vault.create_vault(seed, temp_dir)
            
            # Remove some share files to simulate insufficient shares
            shares_dir = os.path.join(temp_dir, "shares")
            share_files = sorted([f for f in os.listdir(shares_dir) if f.startswith("share_")])
            
            # Remove 3 files, leaving only 3 shares (need 4)
            for i in range(3):
                os.remove(os.path.join(shares_dir, share_files[i]))
            
            # Should fail with insufficient shares
            with pytest.raises(ValueError):
                QuantumSecretVault.recover_vault(temp_dir, passphrase) 