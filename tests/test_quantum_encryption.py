"""
Tests for quantum encryption functionality using post-quantum cryptography.
"""

import pytest
import json
import base64
from src.security.quantum_encryption import QuantumEncryption

class TestQuantumEncryption:
    """Test suite for QuantumEncryption class."""
    
    def test_initialization(self, sample_passphrase):
        """Test QuantumEncryption initialization."""
        enc = QuantumEncryption(sample_passphrase)
        assert enc.passphrase == sample_passphrase
        # Quantum encryption should have default parameters
        assert enc.memory_cost > 0
        assert enc.time_cost > 0
        assert enc.parallelism > 0
    
    def test_initialization_with_custom_argon2_params(self, sample_passphrase):
        """Test QuantumEncryption initialization with custom Argon2 parameters."""
        memory_cost = 1048576  # 1 GiB
        time_cost = 3
        parallelism = 1
        enc = QuantumEncryption(
            passphrase=sample_passphrase,
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism
        )
        assert enc.memory_cost == memory_cost
        assert enc.time_cost == time_cost
        assert enc.parallelism == parallelism
        
        # Test that encryption uses the custom parameters
        data = b"test data"
        encrypted = enc.encrypt(data)
        assert encrypted["memory_cost"] == memory_cost
        assert encrypted["time_cost"] == time_cost
        assert encrypted["parallelism"] == parallelism
    
    def test_liboqs_availability(self):
        """Test that liboqs library is properly loaded and accessible."""
        try:
            # Import should work without errors
            import oqs
            # Should be able to get enabled KEM mechanisms
            kems = oqs.get_enabled_kem_mechanisms()
            assert len(kems) > 0, "No KEM mechanisms enabled"
            
            # Should have Kyber available (most common post-quantum KEM)
            kyber_mechs = [k for k in kems if 'kyber' in k.lower()]
            assert len(kyber_mechs) > 0, "No Kyber mechanisms available"
            
        except ImportError as e:
            pytest.fail(f"liboqs not properly installed: {e}")
        except Exception as e:
            pytest.fail(f"liboqs error: {e}")
    
    def test_encryption_decryption_roundtrip(self, sample_seed, sample_passphrase):
        """Test complete quantum encryption and decryption cycle."""
        enc = QuantumEncryption(sample_passphrase)
        data = sample_seed.encode('utf-8')
        
        # Encrypt
        encrypted = enc.encrypt(data)
        
        # Verify encryption structure
        assert encrypted["encryption_type"] == "Kyber1024"
        assert encrypted["kdf"] == "Argon2id"
        assert "memory_cost" in encrypted
        assert "time_cost" in encrypted
        assert "parallelism" in encrypted
        assert "kyber_public_key" in encrypted
        assert "kyber_ciphertext" in encrypted
        assert "encrypted_private_key" in encrypted
        assert "aes_nonce" in encrypted
        assert "aes_ciphertext" in encrypted
        assert "key_commitment" in encrypted
        
        # Decrypt
        decrypted = enc.decrypt(encrypted)
        
        # Verify data integrity
        assert decrypted == data
        assert decrypted.decode('utf-8') == sample_seed
    
    def test_encryption_with_different_data_sizes(self, sample_passphrase):
        """Test quantum encryption with various data sizes."""
        enc = QuantumEncryption(sample_passphrase)
        
        test_cases = [
            b"short",
            b"medium length string",
            b"very long string " * 100,  # 1700 bytes
            b"",  # empty string
            b"special chars: !@#$%^&*()_+-=[]{}|;:,.<>?",
            bytes(range(256)),  # all possible byte values
        ]
        
        for data in test_cases:
            encrypted = enc.encrypt(data)
            decrypted = enc.decrypt(encrypted)
            assert decrypted == data, f"Failed for data of length {len(data)}"
    
    def test_encryption_uniqueness(self, sample_seed, sample_passphrase):
        """Test that each quantum encryption produces unique ciphertext."""
        enc = QuantumEncryption(sample_passphrase)
        data = sample_seed.encode('utf-8')
        
        # Encrypt same data multiple times
        encrypted1 = enc.encrypt(data)
        encrypted2 = enc.encrypt(data)
        
        # Ciphertexts should be different due to random key generation
        assert encrypted1["kyber_ciphertext"] != encrypted2["kyber_ciphertext"]
        assert encrypted1["aes_ciphertext"] != encrypted2["aes_ciphertext"]
        assert encrypted1["kyber_public_key"] != encrypted2["kyber_public_key"]
        
        # But both should decrypt to the same data
        decrypted1 = enc.decrypt(encrypted1)
        decrypted2 = enc.decrypt(encrypted2)
        assert decrypted1 == decrypted2 == data
    
    def test_key_commitment_security(self, sample_seed, sample_passphrase):
        """Test that key commitment prevents tampering."""
        enc = QuantumEncryption(sample_passphrase)
        data = sample_seed.encode('utf-8')
        
        encrypted = enc.encrypt(data)
        
        # Tamper with the key commitment
        original_commitment = encrypted["key_commitment"]
        encrypted["key_commitment"] = "tampered_commitment_value"
        
        # Decryption should fail due to commitment mismatch
        with pytest.raises(Exception):  # Should raise ValueError or similar
            enc.decrypt(encrypted)
        
        # Restore original commitment - should work again
        encrypted["key_commitment"] = original_commitment
        decrypted = enc.decrypt(encrypted)
        assert decrypted == data
    
    def test_passphrase_sensitivity(self, sample_seed):
        """Test that different passphrases produce different results."""
        passphrase1 = "correct_passphrase"
        passphrase2 = "wrong_passphrase"
        
        enc1 = QuantumEncryption(passphrase1)
        enc2 = QuantumEncryption(passphrase2)
        
        data = sample_seed.encode('utf-8')
        
        # Encrypt with first passphrase
        encrypted = enc1.encrypt(data)
        
        # Try to decrypt with wrong passphrase - should fail
        with pytest.raises(Exception):
            enc2.decrypt(encrypted)
        
        # Decrypt with correct passphrase - should work
        decrypted = enc1.decrypt(encrypted)
        assert decrypted == data
    
    def test_base64_encoding(self, sample_seed, sample_passphrase):
        """Test that quantum encrypted data is properly base64 encoded."""
        enc = QuantumEncryption(sample_passphrase)
        data = sample_seed.encode('utf-8')
        
        encrypted = enc.encrypt(data)
        
        # All binary fields should be valid base64
        binary_fields = [
            "kyber_public_key", "kyber_ciphertext", "encrypted_private_key",
            "aes_nonce", "aes_ciphertext", "key_commitment"
        ]
        
        for field in binary_fields:
            try:
                decoded = base64.b64decode(encrypted[field])
                assert len(decoded) > 0, f"Empty decoded data for {field}"
            except Exception as e:
                pytest.fail(f"Invalid base64 encoding for {field}: {e}")
    
    def test_json_serialization(self, sample_seed, sample_passphrase):
        """Test that quantum encrypted data can be serialized to JSON."""
        enc = QuantumEncryption(sample_passphrase)
        data = sample_seed.encode('utf-8')
        
        encrypted = enc.encrypt(data)
        
        # Should be JSON serializable
        json_str = json.dumps(encrypted)
        parsed = json.loads(json_str)
        
        # Should still decrypt correctly
        decrypted = enc.decrypt(parsed)
        assert decrypted == data
    
    def test_crypto_primitive_security(self, sample_passphrase):
        """Test that quantum encryption uses secure cryptographic primitives."""
        enc = QuantumEncryption(sample_passphrase)
        data = b"security test data"
        
        encrypted = enc.encrypt(data)
        
        # Verify we're using secure algorithms
        assert encrypted["encryption_type"] == "Kyber1024"
        assert encrypted["kdf"] == "Argon2id"
        
        # Verify key sizes are appropriate
        kyber_public_key = base64.b64decode(encrypted["kyber_public_key"])
        kyber_ciphertext = base64.b64decode(encrypted["kyber_ciphertext"])
        
        # Kyber1024 should have specific key/ciphertext sizes
        assert len(kyber_public_key) > 1000, "Kyber public key too small"
        assert len(kyber_ciphertext) > 1000, "Kyber ciphertext too small"
        
        # AES nonce should be appropriate size
        aes_nonce = base64.b64decode(encrypted["aes_nonce"])
        assert len(aes_nonce) == 12, "AES-GCM nonce should be 12 bytes"
    
    def test_performance_timing(self, sample_seed, sample_passphrase):
        """Test that quantum encryption completes in reasonable time."""
        import time
        
        enc = QuantumEncryption(sample_passphrase)
        data = sample_seed.encode('utf-8')
        
        # Encryption should complete in under 10 seconds even on slow systems
        start_time = time.time()
        encrypted = enc.encrypt(data)
        encrypt_time = time.time() - start_time
        
        assert encrypt_time < 10.0, f"Encryption took too long: {encrypt_time:.2f}s"
        
        # Decryption should be much faster
        start_time = time.time()
        decrypted = enc.decrypt(encrypted)
        decrypt_time = time.time() - start_time
        
        assert decrypt_time < 5.0, f"Decryption took too long: {decrypt_time:.2f}s"
        assert decrypted == data
    
    def test_invalid_decryption_data(self, sample_passphrase):
        """Test quantum decryption with invalid data."""
        enc = QuantumEncryption(sample_passphrase)
        
        # Test with missing fields
        invalid_data = {"encryption_type": "Kyber1024"}
        
        with pytest.raises(KeyError):
            enc.decrypt(invalid_data)
        
        # Test with corrupted ciphertext
        data = b"test data"
        encrypted = enc.encrypt(data)
        
        # Corrupt the AES ciphertext
        original_ciphertext = encrypted["aes_ciphertext"]
        encrypted["aes_ciphertext"] = "corrupted_base64_data"
        
        with pytest.raises(Exception):
            enc.decrypt(encrypted) 