#!/bin/bash
# Quantum Secret Vault - Simple Runner
# Usage: ./run.sh "seed phrase" "passphrase" [layers...]
# Example: ./run.sh "word1 ... word24" "passphrase" standard_encryption

# Build the Docker image
echo "Building Docker image..."
docker build -t quantum-secret-vault:latest .

# Run the vault creation
echo "Running vault creation..."
SEED="$1"
PASSPHRASE="$2"
shift 2

# Build layers argument
LAYERS=""
for layer in "$@"; do
    LAYERS="$LAYERS --layers $layer"
done

echo "Creating quantum vault with layers: $@"
echo "Seed: $SEED"
echo "Passphrase: $PASSPHRASE"

# Create output directory
mkdir -p vault_output

# Run the vault creation directly with Python (bypassing entrypoint)
docker run --rm -it \
  -v "$(pwd)/vault_output/:/output/" \
  --entrypoint="" \
  quantum-secret-vault:latest \
  python3 -m src.cli \
  --seed "$SEED" \
  --passphrase "$PASSPHRASE" \
  $LAYERS \
  --output-dir /output

echo "Vault created in vault_output/ directory"
