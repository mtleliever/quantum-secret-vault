"""
Tests for standard AES-256-GCM encryption functionality.
"""

import pytest
import json
import base64
from src.security.standard_encryption import StandardEncryption

class TestStandardEncryption:
    """Test suite for StandardEncryption class."""
    
    def test_initialization(self, sample_passphrase):
        """Test StandardEncryption initialization."""
        enc = StandardEncryption(sample_passphrase)
        assert enc.passphrase == sample_passphrase
        assert len(enc.salt) == 32
    
    def test_initialization_with_custom_salt(self, sample_passphrase):
        """Test StandardEncryption initialization with custom salt."""
        custom_salt = b"custom_salt_32_bytes_long_string"
        enc = StandardEncryption(sample_passphrase, custom_salt)
        assert enc.salt == custom_salt
    
    def test_initialization_with_custom_argon2_params(self, sample_passphrase):
        """Test StandardEncryption initialization with custom Argon2 parameters."""
        memory_cost = 32768  # 32 MiB
        time_cost = 2
        parallelism = 1
        enc = StandardEncryption(sample_passphrase, 
                              memory_cost=memory_cost, 
                              time_cost=time_cost, 
                              parallelism=parallelism)
        assert enc.memory_cost == memory_cost
        assert enc.time_cost == time_cost
        assert enc.parallelism == parallelism
        
        # Test that encryption uses the custom parameters
        data = b"test data"
        encrypted = enc.encrypt(data)
        assert encrypted["memory_cost"] == memory_cost
        assert encrypted["time_cost"] == time_cost
        assert encrypted["parallelism"] == parallelism
    
    def test_key_derivation(self, sample_passphrase):
        """Test Argon2id key derivation."""
        enc = StandardEncryption(sample_passphrase)
        key = enc.derive_key()
        
        # Key should be 32 bytes (256 bits)
        assert len(key) == 32
        assert isinstance(key, bytes)
    
    def test_encryption_decryption_roundtrip(self, sample_seed, sample_passphrase):
        """Test complete encryption and decryption cycle."""
        enc = StandardEncryption(sample_passphrase)
        data = sample_seed.encode('utf-8')
        
        # Encrypt
        encrypted = enc.encrypt(data)
        
        # Verify encryption structure
        assert encrypted["encryption_type"] == "AES-256-GCM"
        assert encrypted["kdf"] == "Argon2id"
        assert encrypted["memory_cost"] == 524288  # 512 MiB default
        assert encrypted["time_cost"] == 5  # 5 iterations default
        assert encrypted["parallelism"] == 1  # 1 thread default
        assert "salt" in encrypted
        assert "nonce" in encrypted
        assert "ciphertext" in encrypted
        
        # Decrypt
        decrypted = enc.decrypt(encrypted)
        
        # Verify data integrity
        assert decrypted == data
        assert decrypted.decode('utf-8') == sample_seed
    
    def test_encryption_with_different_data_sizes(self, sample_passphrase):
        """Test encryption with various data sizes."""
        enc = StandardEncryption(sample_passphrase)
        
        test_cases = [
            b"short",
            b"medium length string",
            b"very long string " * 100,  # 1700 bytes
            b"",  # empty string
        ]
        
        for data in test_cases:
            encrypted = enc.encrypt(data)
            decrypted = enc.decrypt(encrypted)
            assert decrypted == data
    
    def test_encryption_uniqueness(self, sample_seed, sample_passphrase):
        """Test that each encryption produces unique ciphertext."""
        enc = StandardEncryption(sample_passphrase)
        data = sample_seed.encode('utf-8')
        
        # Encrypt same data multiple times
        encrypted1 = enc.encrypt(data)
        encrypted2 = enc.encrypt(data)
        
        # Ciphertexts should be different due to random nonce
        assert encrypted1["ciphertext"] != encrypted2["ciphertext"]
        assert encrypted1["nonce"] != encrypted2["nonce"]
        
        # But both should decrypt to the same data
        decrypted1 = enc.decrypt(encrypted1)
        decrypted2 = enc.decrypt(encrypted2)
        assert decrypted1 == decrypted2 == data
    
    def test_salt_persistence(self, sample_seed, sample_passphrase):
        """Test that salt is preserved across encryption/decryption."""
        enc = StandardEncryption(sample_passphrase)
        data = sample_seed.encode('utf-8')
        
        encrypted = enc.encrypt(data)
        original_salt = encrypted["salt"]
        
        # Create new instance with same passphrase but different salt
        enc2 = StandardEncryption(sample_passphrase)
        encrypted2 = enc2.encrypt(data)
        
        # Salts should be different
        assert encrypted["salt"] != encrypted2["salt"]
        
        # But both should decrypt correctly with their respective instances
        decrypted1 = enc.decrypt(encrypted)
        decrypted2 = enc2.decrypt(encrypted2)
        assert decrypted1 == decrypted2 == data
    
    def test_invalid_decryption_data(self, sample_passphrase):
        """Test decryption with invalid data."""
        enc = StandardEncryption(sample_passphrase)
        
        # Test with missing fields
        invalid_data = {"encryption_type": "AES-256-GCM"}
        
        with pytest.raises(KeyError):
            enc.decrypt(invalid_data)
    
    def test_base64_encoding(self, sample_seed, sample_passphrase):
        """Test that encrypted data is properly base64 encoded."""
        enc = StandardEncryption(sample_passphrase)
        data = sample_seed.encode('utf-8')
        
        encrypted = enc.encrypt(data)
        
        # All string fields should be valid base64
        try:
            base64.b64decode(encrypted["salt"])
            base64.b64decode(encrypted["nonce"])
            base64.b64decode(encrypted["ciphertext"])
        except Exception as e:
            pytest.fail(f"Invalid base64 encoding: {e}")
    
    def test_json_serialization(self, sample_seed, sample_passphrase):
        """Test that encrypted data can be serialized to JSON."""
        enc = StandardEncryption(sample_passphrase)
        data = sample_seed.encode('utf-8')
        
        encrypted = enc.encrypt(data)
        
        # Should be JSON serializable
        json_str = json.dumps(encrypted)
        parsed = json.loads(json_str)
        
        # Should still decrypt correctly
        decrypted = enc.decrypt(parsed)
        assert decrypted == data 