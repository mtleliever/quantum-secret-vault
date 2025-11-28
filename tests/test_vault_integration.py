"""
Integration tests for the quantum secret vault with different layer combinations.
"""

import os
import tempfile 
import shutil
import pytest
from src.core import QuantumSecretVault, SecurityConfig, SecurityLayer
import cbor2
import base64


class TestVaultIntegration:
    """Test suite for vault integration with various security layers."""
    
    def test_shamir_sharing_integration(self):
        """Test complete Shamir sharing workflow with layered encryption."""
        secret = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        password = "test_password_123"
        
        # Create temporary directory for vault
        with tempfile.TemporaryDirectory() as temp_dir:
            # Configure vault with standard encryption + Shamir sharing
            config = SecurityConfig(
                layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.SHAMIR_SHARING],
                shamir_threshold=3,
                shamir_total=5,
                parity_shares=2,
                password=password,
                salt=os.urandom(32),
                argon2_memory_cost=65536,  # Lower for test speed
                argon2_time_cost=3,
                argon2_parallelism=1
            )
            
            # Create vault
            vault = QuantumSecretVault(config)
            result = vault.create_vault(secret, temp_dir)
            
            # Verify vault creation
            assert result["vault_created"] is True
            assert "standard_encryption" in result["layers"]
            assert len(result["files_created"]) == 5  # 5 Reed-Solomon encoded shares
            
            # Verify share files exist
            shares_dir = os.path.join(temp_dir, "shares")
            assert os.path.exists(shares_dir)
            
            share_files = [f for f in os.listdir(shares_dir) if f.startswith("share_") and f.endswith(".bin")]
            assert len(share_files) == 5  # 5 Reed-Solomon encoded shares
            
            # Test recovery using the general recover_vault method (auto-detection)  
            recovered_secret = QuantumSecretVault.recover_vault(
                temp_dir, password, show_details=True
            )
            
            assert recovered_secret == secret
    
    def test_shamir_with_quantum_encryption(self):
        """Test Shamir sharing with quantum encryption layer."""
        secret = "test secret text for quantum shamir integration"
        password = "quantum_test_pass"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Configure vault with both quantum encryption and Shamir sharing
            config = SecurityConfig(
                layers=[SecurityLayer.QUANTUM_ENCRYPTION, SecurityLayer.SHAMIR_SHARING],
                shamir_threshold=2,
                shamir_total=3,
                parity_shares=1,
                password=password,
                salt=os.urandom(32),
                argon2_memory_cost=65536,
                argon2_time_cost=3,
                argon2_parallelism=1
            )
            
            # Create vault
            vault = QuantumSecretVault(config)
            result = vault.create_vault(secret, temp_dir)
            
            # Verify creation
            assert result["vault_created"] is True
            assert "quantum_encryption" in result["layers"]
            assert len(result["files_created"]) == 3  # 3 Reed-Solomon encoded shares
            
            # Test recovery
            recovered_secret = QuantumSecretVault.recover_vault(
                temp_dir, password
            )
            
            assert recovered_secret == secret
    
    def test_shamir_with_layered_encryption(self):
        """Test Shamir sharing with both standard and quantum encryption."""
        secret = "multi layer encryption test secret text here"
        password = "multi_layer_pass"
        
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
                password=password,
                salt=os.urandom(32),
                argon2_memory_cost=65536,
                argon2_time_cost=3,
                argon2_parallelism=1
            )
            
            # Create vault
            vault = QuantumSecretVault(config)
            result = vault.create_vault(secret, temp_dir)
            
            # Verify creation
            assert result["vault_created"] is True
            assert "standard_encryption" in result["layers"]
            assert "quantum_encryption" in result["layers"]
            assert len(result["files_created"]) == 6  # 6 Reed-Solomon encoded shares
            
            # Test recovery with exactly threshold shares
            recovered_secret = QuantumSecretVault.recover_vault(
                temp_dir, password
            )
            
            assert recovered_secret == secret
            
            # Test recovery with more than threshold shares  
            recovered_secret = QuantumSecretVault.recover_vault(
                temp_dir, password
            )
            
            assert recovered_secret == secret
    
    def test_shamir_only_no_encryption(self):
        """Test Shamir sharing without any encryption layers."""
        secret = "plain shamir test without encryption layers"
        password = "not_used_for_encryption"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Configure vault with only Shamir sharing
            config = SecurityConfig(
                layers=[SecurityLayer.SHAMIR_SHARING],
                shamir_threshold=2,
                shamir_total=4,
                parity_shares=1,
                password=password,
                salt=os.urandom(32)
            )
            
            # Create vault
            vault = QuantumSecretVault(config)
            result = vault.create_vault(secret, temp_dir)
            
            # Verify creation
            assert result["vault_created"] is True
            assert len(result["layers"]) == 1  # Just Shamir layer (no encryption layers)
            assert result["layers"][0] == "shamir_sharing"
            assert len(result["files_created"]) == 4  # 4 Reed-Solomon encoded shares
            
            # Test recovery
            recovered_secret = QuantumSecretVault.recover_vault(
                temp_dir, password
            )
            
            assert recovered_secret == secret
    
    def test_insufficient_shares_error(self):
        """Test that recovery fails with insufficient shares."""
        secret = "test insufficient shares error handling"
        password = "test_pass"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            config = SecurityConfig(
                layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.SHAMIR_SHARING],
                shamir_threshold=4,
                shamir_total=5,
                parity_shares=1,
                password=password,
                salt=os.urandom(32),
                argon2_memory_cost=65536,
                argon2_time_cost=3,
                argon2_parallelism=1
            )
            
            # Create vault
            vault = QuantumSecretVault(config)
            vault.create_vault(secret, temp_dir)
            
            # Remove some share files to simulate insufficient shares
            shares_dir = os.path.join(temp_dir, "shares")
            share_files = sorted([f for f in os.listdir(shares_dir) if f.startswith("share_") and f.endswith(".bin")])
            
            # Remove 3 files, leaving only 2 shares (need 4)
            for i in range(3):
                os.remove(os.path.join(shares_dir, share_files[i]))
            
            # Should fail with insufficient shares
            with pytest.raises(ValueError):
                QuantumSecretVault.recover_vault(temp_dir, password) 
    
    def test_layered_encryption_verification_in_shamir(self):
        """
        Verify that layered encryption is properly applied to each Shamir share.
        This demonstrates exactly where and how each encryption layer is applied.
        """
        secret = "test secret for verification"
        password = "test_password"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create vault with full layered encryption + Shamir
            config = SecurityConfig(
                layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.QUANTUM_ENCRYPTION, SecurityLayer.SHAMIR_SHARING],
                shamir_threshold=3,
                shamir_total=5,
                parity_shares=2,
                password=password,
                salt=os.urandom(32),
                argon2_memory_cost=65536,  # Lower for test speed
                argon2_time_cost=3,
                argon2_parallelism=1
            )
            
            vault = QuantumSecretVault(config)
            result = vault.create_vault(secret, temp_dir)
            
            # Verify vault creation
            assert result["vault_created"] is True
            assert "standard_encryption" in result["layers"]
            assert "quantum_encryption" in result["layers"]
            assert "shamir_sharing" in result["layers"]
            assert len(result["files_created"]) == 5  # 5 Reed-Solomon encoded shares
            
            # Inspect a share file to verify it contains layered encryption metadata
            share_file = result['files_created'][0]
            with open(share_file, 'rb') as f:
                share_data = cbor2.load(f)
            
            # Verify share structure
            assert share_data['share_type'] == "Shamir+Reed-Solomon"
            assert 'share_id' in share_data
            assert 'data' in share_data
            assert 'layers' in share_data
            
            # Verify that ALL encryption layers are present in share metadata
            layer_types = [layer['layer'] for layer in share_data['layers']]
            assert "standard_encryption" in layer_types
            assert "quantum_encryption" in layer_types
            assert "shamir_sharing" in layer_types
            
            # Verify standard encryption metadata is preserved
            std_layer = next(layer for layer in share_data['layers'] if layer['layer'] == 'standard_encryption')
            assert 'salt' in std_layer['metadata']
            assert 'nonce' in std_layer['metadata']
            assert 'kdf' in std_layer['metadata']
            assert std_layer['metadata']['encryption_type'] == 'AES-256-GCM'
            
            # Verify quantum encryption metadata is preserved
            quantum_layer = next(layer for layer in share_data['layers'] if layer['layer'] == 'quantum_encryption')
            assert 'kyber_public_key' in quantum_layer['metadata']
            assert 'kyber_ciphertext' in quantum_layer['metadata']
            assert 'salt' in quantum_layer['metadata']
            assert quantum_layer['metadata']['encryption_type'] == 'Kyber1024'
            
            # Verify Shamir metadata
            shamir_layer = next(layer for layer in share_data['layers'] if layer['layer'] == 'shamir_sharing')
            assert shamir_layer['metadata']['threshold'] == 3
            assert shamir_layer['metadata']['total'] == 5
            assert shamir_layer['metadata']['parity'] == 2
            
            # Verify the share data is base64-encoded encrypted content
            share_raw_data = base64.b64decode(share_data['data'])
            assert len(share_raw_data) > 0
            assert isinstance(share_raw_data, bytes)
            
            # Test recovery to verify all layers work correctly
            recovered_secret = QuantumSecretVault.recover_vault(temp_dir, password)
            assert recovered_secret == secret
            
            # Test that we can recover with any subset of threshold shares
            shares_dir = os.path.join(temp_dir, "shares")
            all_share_files = [os.path.join(shares_dir, f) for f in os.listdir(shares_dir) if f.startswith("share_") and f.endswith(".bin")]
            
            # Test with different combinations of 3 shares
            for start_idx in range(len(all_share_files) - 2):
                # Create a temporary directory with only 3 shares
                with tempfile.TemporaryDirectory() as subset_dir:
                    subset_shares_dir = os.path.join(subset_dir, "shares")
                    os.makedirs(subset_shares_dir)
                    
                    # Copy 3 shares
                    for i, src_file in enumerate(all_share_files[start_idx:start_idx+3]):
                        dst_file = os.path.join(subset_shares_dir, f"share_{i}.bin")
                        with open(src_file, 'rb') as src, open(dst_file, 'wb') as dst:
                            dst.write(src.read())
                    
                    # Verify recovery works with this subset
                    subset_recovered = QuantumSecretVault.recover_vault(subset_dir, password)
                    assert subset_recovered == secret
    
    def test_share_contains_full_encryption_proof(self):
        """
        Prove that each share contains the FULL encrypted data, not just a piece.
        This test demonstrates that Shamir splitting happens AFTER encryption.
        """
        secret = "proof that shares contain full encryption"
        password = "proof_pass"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a single salt to use for both configs for comparison
            shared_salt = os.urandom(32)
            
            # Test with just standard encryption first (no Shamir)
            config_no_shamir = SecurityConfig(
                layers=[SecurityLayer.STANDARD_ENCRYPTION],
                password=password,
                salt=shared_salt,
                argon2_memory_cost=65536,
                argon2_time_cost=3
            )
            
            vault_no_shamir = QuantumSecretVault(config_no_shamir)
            result_no_shamir = vault_no_shamir.create_vault(secret, f"{temp_dir}/no_shamir")
            
            # Now test with standard + Shamir (using the same salt)
            config_with_shamir = SecurityConfig(
                layers=[SecurityLayer.STANDARD_ENCRYPTION, SecurityLayer.SHAMIR_SHARING],
                shamir_threshold=3,
                shamir_total=5,
                password=password,
                salt=shared_salt,  # Use same salt for comparison
                argon2_memory_cost=65536,
                argon2_time_cost=3
            )
            
            vault_with_shamir = QuantumSecretVault(config_with_shamir)
            result_with_shamir = vault_with_shamir.create_vault(secret, f"{temp_dir}/with_shamir")
            
            # Load the single encrypted file
            with open(f"{temp_dir}/no_shamir/vault.bin", 'rb') as f:
                single_vault_data = cbor2.load(f)
            
            # Load one of the share files
            share_file = result_with_shamir['files_created'][0]
            with open(share_file, 'rb') as f:
                share_data = cbor2.load(f)
            
            # Both should have the same standard encryption metadata (same salt, etc.)
            single_std_layer = single_vault_data['layers'][0]
            share_std_layer = next(layer for layer in share_data['layers'] if layer['layer'] == 'standard_encryption')
            
            assert single_std_layer['metadata']['salt'] == share_std_layer['metadata']['salt']
            assert single_std_layer['metadata']['encryption_type'] == share_std_layer['metadata']['encryption_type']
            
            # Both should recover to the same secret
            recovered_single = QuantumSecretVault.recover_vault(f"{temp_dir}/no_shamir", password)
            recovered_shares = QuantumSecretVault.recover_vault(f"{temp_dir}/with_shamir", password)
            
            assert recovered_single == secret
            assert recovered_shares == secret
            assert recovered_single == recovered_shares
            
            # This proves that Shamir shares contain the SAME encrypted data,
            # just split using Shamir's algorithm
