# QuantumSeedVault 🔒🌍🔑  

![Docker](https://img.shields.io/badge/Docker-✓-blue?logo=docker)  
![Quantum-Safe](https://img.shields.io/badge/Quantum_Resistant-✓-green)  
![Steganography](https://img.shields.io/badge/Steganography-✓-orange)  

A secure toolkit to split, encrypt, and hide text secrets using **quantum-resistant cryptography** and **steganography**.  

---

## Features  
- **Shamir Secret Sharing (SSS)**: Split text secrets into *n*-of-*m* shares.  
- **Post-Quantum Encryption**: Hybrid AES-256-GCM + Kyber-1024 (NIST-standardized).  
- **Reed-Solomon Codes**: Recover corrupted/lost shares.  
- **Steganography**: Hide shares in PNG/BMP images.  
- **Dockerized**: No host dependencies.  

---

## Installation  

1. **Clone the Repository**:  
   ```bash  
   git clone https://github.com/yourusername/QuantumSeedVault.git  
   cd quantum-secret-vault
   ```

2. **Build the Docker Image**:
   ```bash
   chmod +x build.sh run.sh  
   ./build.sh  # Builds 'quantum-vault:1.0' image  
   ```

## Usage

1. **Prepare Inputs**

Place lossless PNG/BMP images (one per share) in ./input_images/:

  ```bash
  mkdir -p input_images vault_output  
  cp ~/my_images/*.png input_images/  
  ```

2. **Run the Vault Creator**
  ```bash
  ./run.sh "<text secret>" "<25th passphrase>" <shamir_threshold> <shamir_total> <parity_shares>  
  
  # Example (5-of-7 Shamir + 2 parity shares):  
  ./run.sh "word1 word2 ... word24" "my_25th_word" 5 7 2  
  ```

3. **Output Artifacts**

Generated in `./vault_output/`:

- Encrypted shares (AES + Kyber)
- Stego images with hidden shares
- Recovery scripts and documentation
- Inventory CSV for tracking vaults

## Recovery Process

1. Retrieve stego images and kyber_private_keys/ from geographic vaults.
2. Run the recovery script:

  ```bash
  docker run --rm -it -v $(pwd)/vault_output:/vault ubuntu:22.04  
  cd /vault && ./recovery_script.sh stego_images/ recovered_seed.txt
  ```

## Security Notes

- Air-Gapped Execution: Run offline.
- Test First: Validate with dummy data.
