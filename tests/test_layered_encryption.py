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
            
            # Verify layered structure - now in layer_results field
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
            
            # Verify layered structure - now in layer_results field
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
            
            # Verify encryption info is preserved in layer_results
            assert "layer_results" in result
            assert len(result["layer_results"]) == 2
            
            # Find standard encryption layer
            std_layer = next(layer for layer in result["layer_results"] if layer["layer"] == "standard_encryption")
            std_metadata = std_layer["metadata"]
            assert std_metadata["memory_cost"] == 131072
            assert std_metadata["time_cost"] == 3
            assert std_metadata["parallelism"] == 1
            assert std_metadata["kdf"] == "Argon2id"
            
            # Find quantum encryption layer
            qe_layer = next(layer for layer in result["layer_results"] if layer["layer"] == "quantum_encryption")
            qe_metadata = qe_layer["metadata"]
            assert qe_metadata["memory_cost"] == 131072
            assert qe_metadata["time_cost"] == 3
            assert qe_metadata["parallelism"] == 1
            assert qe_metadata["kdf"] == "Argon2id"
            
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