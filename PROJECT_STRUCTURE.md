# Quantum Secret Vault - Project Structure

This document describes the modular architecture of the Quantum Secret Vault project.

## 📁 Directory Structure

```
quantum-secret-vault/
├── src/                           # Main source code
│   ├── __init__.py               # Package initialization
│   ├── quantum_secret_vault.py   # Main entry point
│   ├── cli.py                    # Command-line interface
│   ├── core/                     # Core vault functionality
│   │   ├── __init__.py
│   │   ├── config.py             # Security configuration classes
│   │   └── vault.py              # Main vault orchestrator
│   ├── security/                 # Security layer implementations
│   │   ├── __init__.py
│   │   ├── standard_encryption.py # AES-256-GCM encryption
│   │   ├── quantum_encryption.py  # Kyber-1024 encryption
│   │   ├── shamir_sharing.py     # Secret sharing
│   │   └── steganography.py      # Data hiding in images
│   └── utils/                    # Utility functions
│       ├── __init__.py
│       ├── validation.py         # Input validation
│       └── file_utils.py         # File operations
├── requirements.txt              # Python dependencies
├── dockerfile                   # Docker configuration
├── build.sh                     # Docker build script
├── run.sh                       # Docker run script
├── entrypoint.sh                # Container entrypoint
├── README.md                    # User documentation
├── PROJECT_STRUCTURE.md         # This file
└── LICENSE                      # MIT License
```

## 🏗️ Architecture Overview

### **Core Module (`src/core/`)**
- **`config.py`**: Defines `SecurityLayer` enum and `SecurityConfig` dataclass
- **`vault.py`**: Main `QuantumSecretVault` class that orchestrates all security layers

### **Security Module (`src/security/`)**
- **`standard_encryption.py`**: AES-256-GCM with PBKDF2 key derivation
- **`quantum_encryption.py`**: Kyber-1024 post-quantum encryption
- **`shamir_sharing.py`**: Shamir secret sharing with Reed-Solomon error correction
- **`steganography.py`**: Steghide-based data hiding in images

### **Utilities Module (`src/utils/`)**
- **`validation.py`**: Input validation for seed phrases and passphrases
- **`file_utils.py`**: Safe file operations with atomic writes

### **CLI Module (`src/cli.py`)**
- Command-line argument parsing and validation
- User-friendly error handling
- Comprehensive help documentation

## 🔧 Module Dependencies

```
src/
├── quantum_secret_vault.py
│   └── cli.py
│       └── core/
│           ├── config.py
│           └── vault.py
│               ├── security/
│               │   ├── standard_encryption.py
│               │   ├── quantum_encryption.py
│               │   ├── shamir_sharing.py
│               │   └── steganography.py
│               └── utils/
│                   ├── validation.py
│                   └── file_utils.py
```

## 🎯 Design Principles

### **1. Separation of Concerns**
- Each security layer is implemented in its own module
- Core vault logic is separate from security implementations
- CLI handling is isolated from business logic

### **2. Modularity**
- Security layers can be easily added, removed, or modified
- Each module has a clear, single responsibility
- Dependencies are explicit and minimal

### **3. Extensibility**
- New security layers can be added by implementing the same interface
- Configuration system supports easy parameter changes
- Utility functions are reusable across modules

### **4. Maintainability**
- Clear module boundaries and responsibilities
- Comprehensive documentation and type hints
- Consistent coding style and patterns

## 🔄 Data Flow

### **Encryption Flow**
1. **CLI** → Parses arguments and validates input
2. **Config** → Creates security configuration
3. **Vault** → Orchestrates encryption process
4. **Security Layers** → Apply encryption in sequence:
   - Standard Encryption (AES-256-GCM)
   - Quantum Encryption (Kyber-1024)
   - Shamir Sharing (if enabled)
   - Steganography (if enabled)
5. **File Utils** → Safely write output files

### **Layer Application Order**
```
Input Seed
    ↓
Standard Encryption (if enabled)
    ↓
Quantum Encryption (if enabled)
    ↓
Shamir Sharing (if enabled)
    ↓
Steganography (if enabled)
    ↓
Output Files
```

## 🧪 Testing Structure

Each module can be tested independently:

- **Unit Tests**: Test individual security layers
- **Integration Tests**: Test layer combinations
- **End-to-End Tests**: Test complete vault creation and recovery

## 📦 Package Structure

The project is organized as a Python package with:

- **Public API**: Exposed through `src/__init__.py`
- **Internal Modules**: Organized by functionality
- **Entry Points**: Clear separation between CLI and library usage

## 🔒 Security Considerations

- **Isolation**: Each security layer is isolated and can be audited independently
- **Configuration**: Security parameters are centralized and validated
- **Error Handling**: Graceful failure without exposing sensitive information
- **File Operations**: Atomic writes prevent data corruption

## 🚀 Usage Examples

### **As a Library**
```python
from src.core import QuantumSecretVault, SecurityConfig, SecurityLayer

config = SecurityConfig(
    layers=[SecurityLayer.QUANTUM_ENCRYPTION],
    passphrase="my_passphrase"
)
vault = QuantumSecretVault(config)
result = vault.create_vault("my seed phrase", "output_dir")
```

### **As a CLI Tool**
```bash
python -m src.cli --seed "word1 ... word24" --passphrase "passphrase" --layers quantum_encryption
```

This modular structure makes the codebase maintainable, testable, and extensible while preserving the security and functionality of the quantum secret vault system. 