#!/bin/bash

# Create output directory if missing
mkdir -p /output/stego_images /output/encrypted_shares /output/kyber_private_keys

# Execute the Python script with mounted volumes
python3 /app/quantum_seed_vault.py \
  --seed "$SEED" \
  --images "${IMAGES[@]}" \
  --shares $SHAMIR_THRESHOLD $SHAMIR_TOTAL \
  --parity $PARITY \
  --output-dir /output \
  --passphrase "$PASSPHRASE"

# Fix permissions for host access
chown -R 1000:1000 /output
