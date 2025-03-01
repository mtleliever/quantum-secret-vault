import argparse
import os
import json
import base64
import csv
import subprocess
from secretsharing import SecretSharer
from reedsolo import RSCodec
from argon2 import PasswordHasher
from pqcrypto.kem.kyber_1024 import generate_keypair, encrypt, decrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from stegano import lsb

def split_and_encrypt(seed, shamir_threshold, shamir_shares, parity_shares, passphrase, output_dir):
    # Create directories
    os.makedirs(f"{output_dir}/encrypted_shares", exist_ok=True)
    os.makedirs(f"{output_dir}/kyber_private_keys", exist_ok=True)
    os.makedirs(f"{output_dir}/stego_images", exist_ok=True)

    # Split seed into Shamir shares
    shares = SecretSharer.split_secret(seed, shamir_threshold, shamir_shares)
    
    # Add Reed-Solomon parity
    rsc = RSCodec(parity_shares)
    encoded_shares = rsc.encode([s.encode('utf-8') for s in shares])
    total_shares = len(encoded_shares)
    
    # Derive Argon2 key from passphrase
    ph = PasswordHasher(time_cost=4, memory_cost=2**20, parallelism=4)
    master_key = ph.hash(passphrase)
    
    # Encrypt each share with AES-256-GCM + Kyber-1024
    inventory = []
    for i, share in enumerate(encoded_shares):
        # Generate Kyber keypair
        pubkey, privkey = generate_keypair()
        
        # AES-256-GCM encryption
        aes_key = os.urandom(32)
        nonce = os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, share, None)
        
        # Kyber encapsulation
        kyber_ct, kyber_ss = encrypt(pubkey, aes_key)
        
        # Save encrypted share as JSON
        share_data = {
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "kyber_pubkey": base64.b64encode(pubkey).decode('utf-8'),
            "kyber_ciphertext": base64.b64encode(kyber_ct).decode('utf-8')
        }
        with open(f"{output_dir}/encrypted_shares/share_{i}.json", 'w') as f:
            json.dump(share_data, f)
        
        # Save Kyber private key
        with open(f"{output_dir}/kyber_private_keys/kyber_priv_{i}.bin", 'wb') as f:
            f.write(privkey)
        
        inventory.append({
            "share_id": i,
            "type": "Shamir" if i < shamir_shares else "Parity",
            "kyber_priv_path": f"kyber_private_keys/kyber_priv_{i}.bin",
            "geographic_location": "TBD"
        })
    
    # Generate inventory CSV
    with open(f"{output_dir}/inventory.csv", 'w') as f:
        writer = csv.DictWriter(f, fieldnames=["share_id", "type", "kyber_priv_path", "geographic_location"])
        writer.writeheader()
        writer.writerows(inventory)
    
    return total_shares

def embed_shares(images, output_dir):
    # Verify image count matches shares
    encrypted_shares = os.listdir(f"{output_dir}/encrypted_shares")
    if len(images) != len(encrypted_shares):
        raise ValueError(f"Need {len(encrypted_shares)} images, got {len(images)}")
    
    # Embed each share into an image
    for i, img_path in enumerate(images):
        # Use steghide for better robustness
        output_img = f"{output_dir}/stego_images/share_{i}.png"
        cmd = [
            "steghide",
            "embed",
            "-ef", f"{output_dir}/encrypted_shares/share_{i}.json",
            "-cf", img_path,
            "-p", "QuantumVault2024!",
            "-sf", output_img
        ]
        subprocess.run(cmd, check=True)

def generate_recovery_instructions(output_dir, total_shares):
    # Create README
    readme = f"""QUANTUM SEED VAULT RECOVERY GUIDE

1. Prerequisites:
   - Install steghide, Python 3.10+, and dependencies:
     pip install cryptography pqcrypto-kem-kyber reedsolo

2. Recover Shares:
   - Retrieve images from geographic vaults (see inventory.csv)
   - Extract JSONs: 
       steghide extract -sf stego_images/share_X.png -p "QuantumVault2024!" -xf share_X.json

3. Decrypt Shares:
   - Use recovery_script.sh (requires {total_shares//2 +1} shares)
   
4. Combine Shares:
   - Run: python3 -m secretsharing combine -t 5 -T 7 decrypted_shares/*.txt
"""
    with open(f"{output_dir}/README.txt", 'w') as f:
        f.write(readme)
    
    # Create recovery script template
    recovery_script = """#!/bin/bash
# Usage: ./recovery_script.sh [STEGO_IMAGES_DIR] [OUTPUT_SEED.txt]
for img in "$1"/*.png; do
    steghide extract -sf "$img" -p "QuantumVault2024!" -xf "decrypted_share_${RANDOM}.json"
done

python3 <<EOF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem.kyber_1024 import decrypt
import base64, json, os

shares = []
for f in os.listdir('.'):
    if f.startswith('decrypted_share'):
        with open(f) as json_file:
            data = json.load(json_file)
            privkey = open(f"kyber_priv_{data['share_id']}.bin", 'rb').read()
            aes_key = decrypt(privkey, base64.b64decode(data['kyber_ciphertext']))
            nonce = base64.b64decode(data['nonce']))
            ciphertext = base64.b64decode(data['ciphertext']))
            share = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
            shares.append(share.decode())

# Combine Shamir + Reed-Solomon
from reedsolo import RSCodec
from secretsharing import SecretSharer
rsc = RSCodec({parity_shares})
corrected_shares = rsc.decode(shares)
seed = SecretSharer.recover_secret(corrected_shares[:5])
with open("$2", 'w') as f:
    f.write(seed)
EOF
"""
    with open(f"{output_dir}/recovery_script.sh", 'w') as f:
        f.write(recovery_script)
    os.chmod(f"{output_dir}/recovery_script.sh", 0o755)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Quantum-Resistant Seed Vault Creator")
    parser.add_argument("--seed", type=str, required=True, help="BIP-39 seed phrase (24 words)")
    parser.add_argument("--images", nargs='+', required=True, help="List of image paths for steganography")
    parser.add_argument("--shares", nargs=2, type=int, required=True, help="Shamir threshold e.g., 5 7")
    parser.add_argument("--parity", type=int, default=2, help="Reed-Solomon parity shares")
    parser.add_argument("--output-dir", type=str, default="quantum_vault", help="Output directory")
    parser.add_argument("--passphrase", type=str, required=True, help="BIP-39 passphrase (25th word)")
    
    args = parser.parse_args()
    
    total = split_and_encrypt(
        args.seed, 
        args.shares[0], 
        args.shares[1], 
        args.parity,
        args.passphrase,
        args.output_dir
    )
    
    embed_shares(args.images, args.output_dir)
    generate_recovery_instructions(args.output_dir, total)
    
    print(f"[+] Quantum vault created in {args.output_dir}")
    print(f"[!] Securely archive kyber_private_keys/ and inventory.csv")
