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
- [Docker](https://docs.docker.com/get-docker/) (Docker Desktop on macOS / Windows)

### Create a Vault

Omit the password to be prompted securely (recommended — keeps it out of shell history).

**macOS / Linux:**
```bash
# Basic encryption (prompts for password)
./run.sh create "my secret text" standard_encryption

# Quantum-resistant encryption
./run.sh create "my secret text" standard_encryption quantum_encryption

# Maximum security with Shamir sharing (3-of-5 shares)
./run.sh create "my secret text" standard_encryption quantum_encryption shamir_sharing --shamir 3 5
```

**Windows (PowerShell):**
```powershell
# Basic encryption (prompts for password)
.\run.ps1 create "my secret text" standard_encryption

# Quantum-resistant encryption
.\run.ps1 create "my secret text" standard_encryption quantum_encryption

# Maximum security with Shamir sharing (3-of-5 shares)
.\run.ps1 create "my secret text" standard_encryption quantum_encryption shamir_sharing --shamir 3 5
```

### Recover a Vault

**macOS / Linux:**
```bash
./run.sh recover vault_output
```

**Windows (PowerShell):**
```powershell
.\run.ps1 recover vault_output
```

You will be prompted for the password. For scripting, you can still pass it as an argument, or set `VAULT_PASSWORD`.
---

## Security Levels

### Standard (Fast)
```bash
./run.sh create "secret" standard_encryption
```

### High Security (1GB memory, 12 iterations)
```bash
./run.sh create "secret" standard_encryption quantum_encryption --memory 1048576 --time 12 --threads 4
```

### Maximum Security (4GB memory, 20 iterations)
```bash
./run.sh create "secret" standard_encryption quantum_encryption --memory 4194304 --time 20 --threads 8
```

### Maximum + Geographic Distribution
```bash
./run.sh create "secret" standard_encryption quantum_encryption shamir_sharing --memory 4194304 --time 20 --threads 8 --shamir 3 5
```

> On Windows, use `.\run.ps1` with the same arguments. Password is prompted if omitted.
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

**macOS / Linux:**
```bash
# 1. Build the secure image (while online)
./build_secure_image.sh

# 2. Disconnect from internet (disable Wi-Fi / unplug Ethernet)

# 3. Run secure workflow (prompts for input securely)
./secure_run.sh
```

**Windows (PowerShell):**
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

**macOS / Linux:**
```bash
./test.sh
```

**Windows (PowerShell):**
```powershell
.\test.ps1
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.
