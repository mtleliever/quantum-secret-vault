# Quantum Secret Vault

A secure toolkit to encrypt text secrets using **layered security** with **quantum-resistant cryptography**.

---

## Security Layers

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Standard** | AES-256-GCM + Argon2id | Current cryptographic best practices |
| **Quantum** | Kyber-1024 | Protection against future quantum computers |
| **Shamir** | k-of-n Secret Sharing + Reed-Solomon | Geographic distribution & redundancy |

---

## Quick Start

### Prerequisites
- Docker

### Create a Vault

```powershell
# Basic encryption
.\run.ps1 create "my secret text" "mypassword" standard_encryption

# Quantum-resistant encryption
.\run.ps1 create "my secret text" "mypassword" standard_encryption quantum_encryption

# Maximum security with Shamir sharing (3-of-5 shares)
.\run.ps1 create "my secret text" "mypassword" standard_encryption quantum_encryption shamir_sharing --shamir 3 5
```

### Recover a Vault

```powershell
.\run.ps1 recover vault_output "mypassword"
```

---

## Security Levels

### Standard (Fast)
```powershell
.\run.ps1 create "secret" "password" standard_encryption
```

### High Security (1GB memory, 12 iterations)
```powershell
.\run.ps1 create "secret" "password" standard_encryption quantum_encryption --memory 1048576 --time 12 --threads 4
```

### Maximum Security (4GB memory, 20 iterations)
```powershell
.\run.ps1 create "secret" "password" standard_encryption quantum_encryption --memory 4194304 --time 20 --threads 8
```

### Maximum + Geographic Distribution
```powershell
.\run.ps1 create "secret" "password" standard_encryption quantum_encryption shamir_sharing --memory 4194304 --time 20 --threads 8 --shamir 3 5
```

---

## Argon2 Parameters

| Parameter | Flag | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| Memory | `--memory` | 512 MiB | 64 MiB - 4 GiB | Memory cost in KiB |
| Time | `--time` | 5 | 1 - 20 | Iterations |
| Threads | `--threads` | 1 | 1 - 8 | Parallel threads |

Higher values = stronger security but slower encryption/decryption.

---

## Air-Gapped Workflow (Maximum Security)

For maximum security, use the air-gapped workflow:

```powershell
# 1. Build the secure image (while online)
.\build_secure_image.ps1

# 2. Disconnect from internet

# 3. Run secure workflow (prompts for input securely)
.\secure_run.ps1
```

This workflow:
- Verifies network is disconnected
- Uses secure input handling (no command history)
- Automatically uses maximum Argon2 parameters
- Securely wipes temporary files after completion

---

## Output Structure

**Without Shamir sharing:**
```
vault_output/
└── vault.bin
```

**With Shamir sharing:**
```
vault_output/
└── shares/
    ├── share_0.bin
    ├── share_1.bin
    └── ...
```

---

## Testing

```powershell
.\test.ps1
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.
