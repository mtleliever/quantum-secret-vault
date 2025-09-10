# Quantum Secret Vault 🔒🌍🔑  

![Docker](https://img.shields.io/badge/Docker-✓-blue?logo=docker)  
![Quantum-Safe](https://img.shields.io/badge/Quantum_Resistant-✓-green)  
![Layered Security](https://img.shields.io/badge/Layered_Security-✓-purple)  
  

A secure toolkit to encrypt and protect text secrets using **layered security architecture** with **quantum-resistant cryptography**.  

---

## 🏗️ Layered Security Architecture

The vault supports **3 security layers** that can be combined in any order:

### 🔐 **Layer 1: Standard Encryption**
- **AES-256-GCM** encryption with **Argon2id** key derivation
- **Configurable memory cost** (512 MiB - 4 GiB) for brute-force resistance
- **Configurable time cost** (5-20 iterations) for enhanced security
- **32-byte salt** for rainbow table protection
- **Best practice** for current cryptographic standards

### ⚛️ **Layer 2: Quantum Encryption** 
- **Kyber-1024** (NIST standardized post-quantum KEM)
- **Hybrid encryption**: Kyber + AES-256-GCM
- **Quantum-resistant** against future quantum computers
- **Forward secrecy** with ephemeral keys

### 🔀 **Layer 3: Shamir Secret Sharing**
- **n-of-m threshold** secret sharing
- **Reed-Solomon error correction** for corrupted shares
- **Geographic distribution** capability
- **Redundancy** against partial compromise



---

## 🚀 Quick Start

### 1. **Create Vaults with Different Security Levels**

#### **Basic Standard Encryption Only**
```bash
./run.sh create "word1 word2 ... word24" "password" standard_encryption
```
*Output: Single encrypted file*

#### **Quantum + Standard Encryption (Default Security)**
```bash
./run.sh create "word1 word2 ... word24" "password" standard_encryption quantum_encryption
```
*Output: Double-encrypted file (AES + Kyber)*

#### **High Security (1GB Memory, 12 Iterations)**
```bash
./run.sh create "word1 word2 ... word24" "password" standard_encryption quantum_encryption --memory 1048576 --time 12 --threads 4
```
*Output: High-security encrypted file with enhanced computational resistance*

#### **Ultra-High Security (4GB Memory, 20 Iterations)**
```bash
./run.sh create "word1 word2 ... word24" "password" standard_encryption quantum_encryption --memory 4194304 --time 20 --threads 8
```
*Output: Ultra-secure encrypted file with maximum computational resistance*

#### **Maximum Security with Geographic Distribution**
```bash
./run.sh create "word1 word2 ... word24" "password" standard_encryption quantum_encryption shamir_sharing --memory 4194304 --time 20 --threads 8 --shamir 3 5
```
*Output: 5 ultra-secure shares (need 3 to recover)*




### 2. **Recover Vault**
```bash
./run.sh recover folder_name_containing_vault_files "password"
```
*Output: The originally secured seedphrase*

---

## 📁 Output Structure

### **Single File Vault** (no Shamir sharing)
```
vault_output/
└── vault.bin                   # Encrypted seed data
```

### **Multi-Share Vault** (with Shamir sharing)
```
vault_output/
└── shares/                     # Encrypted share files
    ├── share_0.bin            # Reed-Solomon encoded Shamir share 0
    ├── share_1.bin            # Reed-Solomon encoded Shamir share 1
    ├── share_2.bin            # Reed-Solomon encoded Shamir share 2
    └── ...
```

---

## ⚙️ Security Parameters

### **Argon2id Key Derivation Settings**

Control the computational cost of brute-force attacks with these parameters:

| Parameter | Flag | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| **Memory** | `--memory` | 512 MiB | 64 MiB - 4 GiB | Memory usage in KiB |
| **Time** | `--time` | 5 | 1 - 20 | Number of iterations |
| **Threads** | `--threads` | 1 | 1 - 8 | Parallel processing threads |

---

## 🔧 Advanced Usage

### **Custom Shamir Parameters with High Security**
```bash
# 3-of-5 sharing with high security parameters
./run.sh create "seed phrase" "passphrase" standard_encryption quantum_encryption shamir_sharing --memory 2097152 --time 15 --threads 4 --shamir 3 5
```

### **Million-Dollar Security Setup**
```bash
# Ultimate protection for high-value assets
./run.sh create "seed phrase" "passphrase" standard_encryption quantum_encryption shamir_sharing --memory 4194304 --time 20 --threads 8 --shamir 3 7 --parity 3
```

### **Fast Testing with Lower Security**
```bash
# Quick testing with minimal security (NOT for real secrets)
./run.sh create "seed phrase" "passphrase" standard_encryption --memory 65536 --time 3 --threads 1
```

### **Custom Security Parameters**
```bash
# Customize any parameter combination
./run.sh create "seed phrase" "passphrase" standard_encryption quantum_encryption \
  --memory 1048576 \    # 1 GB memory
  --time 12 \           # 12 iterations
  --threads 4 \         # 4 parallel threads
  --output-dir my_vault
```

---

## 🔓 Recovery Process

### **1. Standard/Quantum Encryption Recovery**
```python
# Load encrypted data
with open('encrypted_seed.json') as f:
    data = json.load(f)

# Decrypt layers in reverse order
# (Implementation depends on layers used)
```

### **2. Shamir Share Recovery**
```python
# Collect required shares
shares = []
for i in range(threshold):
    with open(f'share_{i}.bin', 'rb') as f:
        share_data = cbor2.load(f)
        shares.append(base64.b64decode(share_data['data']))

# Recover secret  
recovered = shamir.recover_secret(shares)
```



---

## 🛡️ Security Considerations

### **Layer Combinations**
- **Standard + Quantum**: Maximum current + future security
- **Quantum + Shamir**: Quantum-resistant distributed backup
- **All Layers**: Ultimate security but complex recovery

### **Best Practices**
- **Air-gapped execution**: Run offline for maximum security
- **Test recovery**: Always test with dummy data first
- **Secure storage**: Store private keys separately from encrypted data
- **Geographic distribution**: Physically separate Shamir shares

### **Security Levels**

| Configuration | Security Level | Computational Resistance | Use Case |
|---------------|---------------|-------------------------|----------|
| `standard_encryption` (default) | 🔒 Standard | Baseline cryptographic security | Daily use, current threats |
| `quantum_encryption` (default) | ⚛️ Quantum | Post-quantum resistance | Long-term storage, future-proof |
| `standard_encryption` + `quantum_encryption` | 🔒⚛️ Hybrid | Dual-layer protection | Maximum current + future security |
| + High Security Parameters (1GB/12it) | 🔒⚛️🚀 Enhanced | Significantly increased resistance | Extremely sensitive secrets |
| + Ultra-High Parameters (4GB/20it) | 🔒⚛️🚀💎 Ultimate | Maximum computational resistance | High-value asset protection |
| + `shamir_sharing` | 🔀 Distributed | Same + Redundancy | Geographic backup, redundancy |


### **Parameter Impact on Security**
- **Memory Cost**: Exponential impact on computational difficulty (2x memory = 2x harder to attack)
- **Time Cost**: Linear impact on computational difficulty (2x time = 2x harder to attack)  
- **Combined Effect**: Multiplicative security improvement (4GB + 20 iterations = 32x more secure than defaults)

---

## 🧪 Testing

### **Docker Testing**
```bash
# Run tests in Docker container
chmod +x test.sh
./test.sh
```

### **Test Coverage**
- ✅ **AES-256-GCM Encryption**: Key derivation, encryption/decryption, data integrity
- ✅ **Shamir Secret Sharing**: Threshold recovery, error correction, share validation
- ✅ **Vault Integration**: Complete workflow testing, file structure validation
- ✅ **Error Handling**: Invalid inputs, corrupted data, edge cases

---

## 🔧 Technical Details

### **Dependencies**
- **cryptography**: Standard encryption (AES, PBKDF2)
- **secretsharing**: Shamir secret sharing
- **reedsolo**: Reed-Solomon error correction

- **pytest**: Testing framework (optional)
- **argon2-cffi**: Password hashing

### **Cryptographic Standards**
- **AES-256-GCM**: NIST FIPS 197, 800-38D
- **Argon2id**: RFC 9106, memory-hard key derivation (512 MiB - 4 GiB)
- **Kyber-1024**: NIST PQC Round 3 winner (post-quantum KEM)
- **Shamir Secret Sharing**: Adi Shamir's (k,n) threshold scheme
- **Reed-Solomon**: Error correction for corrupted shares

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions welcome! Please see our contributing guidelines for details.
