"""
Tests for layered encryption functionality.
"""

import pytest
import tempfile
import os
import shutil
from src.core.vault import QuantumSecretVault
from src.core.config import SecurityConfig, SecurityLayer


class TestLayeredEncryption:
    """Test suite for layered encryption functionality."""
    
    def test_single_standard_encryption_layer(self, sample_seed, sample_passphrase):
        """Test single layer of standard encryption."""
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION],
            passphrase=sample_passphrase,
            salt=os.urandom(32),
            argon2_memory_cost=65536,  # 64 MiB for faster tests
            argon2_time_cost=2,
            argon2_parallelism=1
        )
        
        vault = QuantumSecretVault(config)
        
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create vault
            result = vault.create_vault(sample_seed, temp_dir)
            
            # Verify creation
            assert result["vault_created"] is True
            assert "standard_encryption" in result["layers"]
            
            # Recover vault
            recovered_seed = QuantumSecretVault.recover_vault(temp_dir, sample_passphrase)
            
            # Verify recovery
            assert recovered_seed == sample_seed
    
    def test_single_quantum_encryption_layer(self, sample_seed, sample_passphrase):
        """Test single layer of quantum encryption."""
        config = SecurityConfig(
            layers=[SecurityLayer.QUANTUM_ENCRYPTION],
            passphrase=sample_passphrase,
            salt=os.urandom(32),
            argon2_memory_cost=65536,  # 64 MiB for faster tests
            argon2_time_cost=2,
            argon2_parallelism=1
        )
        
        vault = QuantumSecretVault(config)
        
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create vault
            result = vault.create_vault(sample_seed, temp_dir)
            
            # Verify creation
            assert result["vault_created"] is True
            assert "quantum_encryption" in result["layers"]
            
            # Recover vault
            recovered_seed = QuantumSecretVault.recover_vault(temp_dir, sample_passphrase)
            
            # Verify recovery
            assert recovered_seed == sample_seed
    
    def test_dual_layer_standard_then_quantum(self, sample_seed, sample_passphrase):
        """Test dual layer: standard encryption followed by quantum encryption."""
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.QUANTUM_ENCRYPTION],
            passphrase=sample_passphrase,
            salt=os.urandom(32),
            argon2_memory_cost=65536,  # 64 MiB for faster tests
            argon2_time_cost=2,
            argon2_parallelism=1
        )
        
        vault = QuantumSecretVault(config)
        
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create vault
            result = vault.create_vault(sample_seed, temp_dir)
            
            # Verify creation
            assert result["vault_created"] is True
            assert "standard_encryption" in result["layers"]
            assert "quantum_encryption" in result["layers"]
            assert result["layers"] == ["standard_encryption", "quantum_encryption"]
            
            # Verify layered structure
            assert "layer_results" in result
            assert len(result["layer_results"]) == 2
            assert result["layer_results"][0]["layer"] == "standard_encryption"
            assert result["layer_results"][1]["layer"] == "quantum_encryption"
            
            # Recover vault
            recovered_seed = QuantumSecretVault.recover_vault(temp_dir, sample_passphrase)
            
            # Verify recovery
            assert recovered_seed == sample_seed
    
    def test_dual_layer_quantum_then_standard(self, sample_seed, sample_passphrase):
        """Test dual layer: quantum encryption followed by standard encryption."""
        config = SecurityConfig(
            layers=[SecurityLayer.QUANTUM_ENCRYPTION, SecurityLayer.STANDARD_ENCRYPTION],
            passphrase=sample_passphrase,
            salt=os.urandom(32),
            argon2_memory_cost=65536,  # 64 MiB for faster tests
            argon2_time_cost=2,
            argon2_parallelism=1
        )
        
        vault = QuantumSecretVault(config)
        
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create vault
            result = vault.create_vault(sample_seed, temp_dir)
            
            # Verify creation
            assert result["vault_created"] is True
            assert "quantum_encryption" in result["layers"]
            assert "standard_encryption" in result["layers"]
            assert result["layers"] == ["quantum_encryption", "standard_encryption"]
            
            # Verify layered structure
            assert "layer_results" in result
            assert len(result["layer_results"]) == 2
            assert result["layer_results"][0]["layer"] == "quantum_encryption"
            assert result["layer_results"][1]["layer"] == "standard_encryption"
            
            # Recover vault
            recovered_seed = QuantumSecretVault.recover_vault(temp_dir, sample_passphrase)
            
            # Verify recovery
            assert recovered_seed == sample_seed
    
    def test_encryption_info_preservation(self, sample_seed, sample_passphrase):
        """Test that encryption info is preserved for all layers."""
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.QUANTUM_ENCRYPTION],
            passphrase=sample_passphrase,
            salt=os.urandom(32),
            argon2_memory_cost=131072,  # 128 MiB
            argon2_time_cost=3,
            argon2_parallelism=1
        )
        
        vault = QuantumSecretVault(config)
        
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create vault
            result = vault.create_vault(sample_seed, temp_dir)
            
            # Verify encryption info
            assert "encryption_info" in result
            assert "standard_encryption" in result["encryption_info"]
            assert "quantum_encryption" in result["encryption_info"]
            
            # Verify standard encryption info
            std_info = result["encryption_info"]["standard_encryption"]
            assert std_info["memory_cost"] == "131072"
            assert std_info["time_cost"] == "3"
            assert std_info["parallelism"] == "1"
            assert std_info["kdf"] == "Argon2id"
            
            # Verify quantum encryption info
            qe_info = result["encryption_info"]["quantum_encryption"]
            assert qe_info["memory_cost"] == 131072
            assert qe_info["time_cost"] == 3
            assert qe_info["parallelism"] == 1
            assert qe_info["kdf"] == "Argon2id"
            
            # Recover vault
            recovered_seed = QuantumSecretVault.recover_vault(temp_dir, sample_passphrase)
            assert recovered_seed == sample_seed
    
    def test_wrong_passphrase_fails(self, sample_seed, sample_passphrase):
        """Test that wrong passphrase fails for layered encryption."""
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.QUANTUM_ENCRYPTION],
            passphrase=sample_passphrase,
            salt=os.urandom(32),
            argon2_memory_cost=65536,  # 64 MiB for faster tests
            argon2_time_cost=2,
            argon2_parallelism=1
        )
        
        vault = QuantumSecretVault(config)
        
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create vault
            vault.create_vault(sample_seed, temp_dir)
            
            # Try to recover with wrong passphrase
            with pytest.raises(ValueError):
                QuantumSecretVault.recover_vault(temp_dir, "wrong_passphrase")
    
    def test_no_encryption_layers(self, sample_seed, sample_passphrase):
        """Test handling of no encryption layers."""
        config = SecurityConfig(
            layers=[],  # No layers
            passphrase=sample_passphrase,
            salt=os.urandom(32),
        )
        
        vault = QuantumSecretVault(config)
        
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create vault
            result = vault.create_vault(sample_seed, temp_dir)
            
            # Verify creation
            assert result["vault_created"] is True
            assert result["layers"] == []
            
            # Recover vault
            recovered_seed = QuantumSecretVault.recover_vault(temp_dir, sample_passphrase)
            
            # Verify recovery
            assert recovered_seed == sample_seed 