# Quantum Secret Vault 🔒🌍🔑  

![Docker](https://img.shields.io/badge/Docker-✓-blue?logo=docker)  
![Quantum-Safe](https://img.shields.io/badge/Quantum_Resistant-✓-green)  
![Layered Security](https://img.shields.io/badge/Layered_Security-✓-purple)  
![Steganography](https://img.shields.io/badge/Steganography-✓-orange)  

A secure toolkit to encrypt and protect text secrets using **layered security architecture** with **quantum-resistant cryptography** and **steganography**.  

---

## 🏗️ Layered Security Architecture

The vault supports **4 security layers** that can be combined in any order:

### 🔐 **Layer 1: Standard Encryption**
- **AES-256-GCM** encryption with **PBKDF2-HMAC-SHA256** key derivation
- **600,000 iterations** for brute-force resistance
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

### 🖼️ **Layer 4: Steganography**
- **Steghide** for robust data hiding in images
- **Plausible deniability** - data looks like normal images
- **Multiple image formats** supported (PNG, BMP, JPEG)

---

## 🚀 Quick Start

### 1. **Create Vaults with Different Security Levels**

#### **Basic Quantum Security Only**
```bash
./run.sh create "word1 word2 ... word24" "password" "quantum_encryption"
```
*Output: Single quantum-encrypted file*

#### **Quantum + Standard Encryption**
```bash
./run.sh create "word1 word2 ... word24" "password" "standard_encryption" "quantum_encryption"
```
*Output: Double-encrypted file (AES + Kyber)*

#### **Quantum + Shamir Sharing**
```bash
./run.sh create "word1 word2 ... word24" "password" "quantum_encryption" "shamir_sharing" 5 7
```
*Output: 7 quantum-encrypted shares (need 5 to recover)*

#### **Full Security Stack**
```bash
./run.sh create "word1 word2 ... word24" "password" "standard_encryption" "quantum_encryption" "shamir_sharing" "steganography" 5 7 image1.png image2.png image3.png image4.png image5.png image6.png image7.png
```
*Output: 7 stego images with hidden encrypted shares*


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
├── encrypted_seed.json          # Encrypted seed data
├── vault_config.json           # Vault configuration
└── stego_images/               # (if steganography enabled)
    └── encrypted_seed.png      # Hidden encrypted data
```

### **Multi-Share Vault** (with Shamir sharing)
```
vault_output/
├── shares/                     # Encrypted share files
│   ├── share_0.json           # Share 0 (Shamir)
│   ├── share_1.json           # Share 1 (Shamir)
│   ├── share_2.json           # Share 2 (Parity)
│   └── ...
├── quantum_keys/              # (if quantum encryption enabled)
│   ├── kyber_priv_0.bin       # Quantum private keys
│   └── ...
├── stego_images/              # (if steganography enabled)
│   ├── share_0.png           # Hidden share 0
│   ├── share_1.png           # Hidden share 1
│   └── ...
└── vault_config.json         # Vault configuration
```

---

## 🔧 Advanced Usage

### **Custom Shamir Parameters**
```bash
# 3-of-5 sharing with 1 parity share
./run.sh "seed phrase" "passphrase" "quantum_encryption" "shamir_sharing" 3 5
```

### **Standard Encryption Only**
```bash
# Just AES-256-GCM encryption
./run.sh "seed phrase" "passphrase" "standard_encryption"
```

### **Steganography Only**
```bash
# Hide unencrypted data in images (not recommended for secrets)
./run.sh "seed phrase" "passphrase" "steganography" image1.png
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
    with open(f'share_{i}.json') as f:
        shares.append(json.load(f)['data'])

# Recover secret
recovered = shamir.recover_secret(shares)
```

### **3. Steganography Recovery**
```bash
# Extract hidden data from images
steghide extract -sf share_0.png -p "QuantumVault2024!" -xf share_0.json
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
| Layers | Security Level | Use Case |
|--------|---------------|----------|
| `standard_encryption` | 🔒 Standard | Daily use, current threats |
| `quantum_encryption` | ⚛️ Quantum | Long-term storage, future-proof |
| `standard_encryption` + `quantum_encryption` | 🔒⚛️ Hybrid | Maximum current + future security |
| + `shamir_sharing` | 🔀 Distributed | Geographic backup, redundancy |
| + `steganography` | 🖼️ Hidden | Plausible deniability, covert ops |

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

See [tests/README.md](tests/README.md) for detailed testing information.

---

## 🔧 Technical Details

### **Dependencies**
- **cryptography**: Standard encryption (AES, PBKDF2)
- **secretsharing**: Shamir secret sharing
- **reedsolo**: Reed-Solomon error correction
- **stegano**: Steganography (Python library)
- **pytest**: Testing framework (optional)
- **argon2-cffi**: Password hashing

### **Cryptographic Standards**
- **AES-256-GCM**: NIST FIPS 197, 800-38D
- **PBKDF2-HMAC-SHA256**: RFC 2898, 600k iterations
- **Kyber-1024**: NIST PQC Round 3 winner
- **Shamir Secret Sharing**: Adi Shamir's (k,n) threshold scheme

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions welcome! Please see our contributing guidelines for details.
