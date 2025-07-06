# Quantum Secret Vault - Test Suite

This directory contains comprehensive tests for the Quantum Secret Vault project.

## Test Structure

```
tests/
├── __init__.py              # Test package initialization
├── conftest.py              # Pytest configuration and fixtures
├── test_standard_encryption.py  # AES-256-GCM encryption tests
├── test_vault_integration.py # Complete vault integration tests
├── requirements.txt         # Test dependencies
└── README.md               # This file
```

## Running Tests

### Option 1: Simple Test Runner (Recommended)

The simplest way to run tests is using the built-in test runner:

```bash
python run_tests.py
```

This runs basic functionality tests without requiring additional dependencies.

### Option 2: Pytest (Advanced)

For more comprehensive testing with pytest:

```bash
# Install test dependencies
pip install -r tests/requirements.txt

# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_standard_encryption.py

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run with verbose output
pytest tests/ -v
```

## Test Coverage

### Standard Encryption Tests (`test_standard_encryption.py`)

Tests AES-256-GCM encryption functionality:

- ✅ Initialization and key derivation
- ✅ Encryption/decryption roundtrip
- ✅ Data integrity verification
- ✅ Encryption uniqueness (nonce randomness)
- ✅ Salt persistence and management
- ✅ Error handling for invalid data
- ✅ Base64 encoding validation
- ✅ JSON serialization compatibility
- ✅ Various data sizes and types



### Vault Integration Tests (`test_vault_integration.py`)

Tests complete vault functionality:

- ✅ AES-only vault creation
- ✅ Shamir-only vault creation
- ✅ Combined AES + Shamir vaults
- ✅ Steganography integration
- ✅ All-layer vaults (AES + Shamir + Stego)
- ✅ Configuration file generation
- ✅ File structure validation
- ✅ Error handling and recovery
- ✅ File permissions

## Test Fixtures

The test suite provides several reusable fixtures:

- `temp_dir`: Temporary directory for test files
- `sample_seed`: Standard BIP-39 seed phrase for testing
- `sample_passphrase`: Test passphrase
- `sample_images`: Sample image files for steganography tests

## Expected Test Results

When all tests pass, you should see output like:

```
🚀 Starting Quantum Secret Vault Tests...

🔐 Testing AES-256-GCM Encryption...
✅ Initialization successful
✅ Key derivation successful
✅ Encryption structure correct
✅ Decryption successful
✅ Encryption uniqueness verified

🔀 Testing Shamir Secret Sharing...
✅ Initialization successful
✅ Secret splitting successful
✅ Secret recovery successful
✅ Share info correct

🏦 Testing Vault Integration...
✅ AES-only vault creation successful
✅ Vault files created
✅ Vault file structure correct

==================================================
📊 TEST RESULTS SUMMARY
==================================================
AES Encryption           ✅ PASS
Shamir Secret Sharing    ✅ PASS
Vault Integration        ✅ PASS
==================================================
Total: 3, Passed: 3, Failed: 0

🎉 All tests passed! Basic functionality is working correctly.
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Make sure you're running tests from the project root directory
2. **Missing Dependencies**: Install required packages with `pip install -r src/requirements.txt`
3. **Permission Errors**: Ensure you have write permissions in the test directory

### Debug Mode

For detailed debugging, run tests with verbose output:

```bash
python run_tests.py 2>&1 | tee test_output.log
```

This will save all test output to `test_output.log` for analysis.

## Adding New Tests

When adding new functionality:

1. Create a new test file following the naming convention `test_*.py`
2. Use the existing fixtures when possible
3. Add comprehensive test cases covering:
   - Happy path scenarios
   - Edge cases and error conditions
   - Performance with large data
   - Security considerations

4. Update this README with new test descriptions

## Security Testing

The test suite includes security-focused tests:

- Encryption strength validation
- Key derivation security
- Randomness verification
- Data integrity checks
- Error handling for malicious input

## Performance Testing

For performance testing, consider adding:

- Large file handling tests
- Memory usage monitoring
- Encryption/decryption speed benchmarks
- Concurrent operation tests 