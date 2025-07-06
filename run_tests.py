#!/usr/bin/env python3
"""
Simple test runner for Quantum Secret Vault.
This script runs basic functionality tests without requiring pytest.
"""

import sys
import os
import tempfile
import shutil
import json
from pathlib import Path

# Add src to path (handle both local and Docker environments)
current_dir = Path(__file__).parent
src_path = current_dir / 'src'
if src_path.exists():
    sys.path.insert(0, str(src_path))
else:
    # In Docker, src is in /app/src
    sys.path.insert(0, '/app/src')

def run_aes_tests():
    """Run AES encryption tests."""
    print("🔐 Testing AES-256-GCM Encryption...")
    
    from src.security.standard_encryption import StandardEncryption
    
    # Test data
    test_seed = "abandon ability able about above absent absorb abstract absurd abuse access accident"
    test_passphrase = "my_test_passphrase_123"
    
    try:
        # Test initialization
        enc = StandardEncryption(test_passphrase)
        print("✅ Initialization successful")
        
        # Test key derivation
        key = enc.derive_key()
        assert len(key) == 32
        print("✅ Key derivation successful")
        
        # Test encryption/decryption
        data = test_seed.encode('utf-8')
        encrypted = enc.encrypt(data)
        
        # Verify structure
        assert encrypted["encryption_type"] == "AES-256-GCM"
        assert encrypted["kdf"] == "PBKDF2-HMAC-SHA256"
        assert encrypted["iterations"] == "600000"
        print("✅ Encryption structure correct")
        
        # Test decryption
        decrypted = enc.decrypt(encrypted)
        assert decrypted == data
        assert decrypted.decode('utf-8') == test_seed
        print("✅ Decryption successful")
        
        # Test uniqueness
        encrypted2 = enc.encrypt(data)
        assert encrypted["ciphertext"] != encrypted2["ciphertext"]
        print("✅ Encryption uniqueness verified")
        
        return True
        
    except Exception as e:
        print(f"❌ AES test failed: {e}")
        return False



def run_vault_tests():
    """Run vault integration tests."""
    print("\n🏦 Testing Vault Integration...")
    
    from src.core import QuantumSecretVault, SecurityConfig, SecurityLayer
    
    test_seed = "abandon ability able about above absent absorb abstract absurd abuse access accident"
    test_passphrase = "my_test_passphrase_123"
    
    # Create temporary directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Test AES only vault
        config = SecurityConfig(
            layers=[SecurityLayer.STANDARD_ENCRYPTION],
            passphrase=test_passphrase,
            salt=os.urandom(32)
        )
        
        vault = QuantumSecretVault(config)
        result = vault.create_vault(test_seed, temp_dir)
        
        assert result["vault_created"] is True
        assert SecurityLayer.STANDARD_ENCRYPTION.value in result["layers_used"]
        print("✅ AES-only vault creation successful")
        
        # Check files
        encrypted_file = os.path.join(temp_dir, "encrypted_seed.json")
        config_file = os.path.join(temp_dir, "vault_config.json")
        
        assert os.path.exists(encrypted_file)
        assert os.path.exists(config_file)
        print("✅ Vault files created")
        
        # Verify file structure
        with open(encrypted_file, 'r') as f:
            data = json.load(f)
        
        assert "encrypted_data" in data
        assert "encryption_info" in data
        print("✅ Vault file structure correct")
        
        return True
        
    except Exception as e:
        print(f"❌ Vault test failed: {e}")
        return False
    
    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)

def run_all_tests():
    """Run all tests and provide summary."""
    print("🚀 Starting Quantum Secret Vault Tests...\n")
    
    tests = [
        ("AES Encryption", run_aes_tests),
        ("Vault Integration", run_vault_tests),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*50)
    print("📊 TEST RESULTS SUMMARY")
    print("="*50)
    
    passed = 0
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{test_name:25} {status}")
        if success:
            passed += 1
    
    print("="*50)
    print(f"Total: {total}, Passed: {passed}, Failed: {total - passed}")
    
    if passed == total:
        print("\n🎉 All tests passed! Basic functionality is working correctly.")
        return True
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Check the output above for details.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1) 