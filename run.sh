#!/bin/bash
# Quantum Secret Vault - Simple Runner
# Usage:
#   ./run.sh create "seed phrase" "passphrase" [layers...]
#   ./run.sh recover <vault_dir> <passphrase>
# Example:
#   ./run.sh create "word1 ... word24" "passphrase" standard_encryption
#   ./run.sh recover vault_output "passphrase"

# Build the Docker image
echo "Building Docker image..."
docker build -t quantum-secret-vault:latest .

MODE="$1"
shift

if [[ "$MODE" == "recover" ]]; then
  VAULT_DIR="$1"
  PASSPHRASE="$2"
  if [[ -z "$VAULT_DIR" || -z "$PASSPHRASE" ]]; then
    echo "Usage: ./run.sh recover <vault_dir> <passphrase>"
    exit 1
  fi
  echo "Running vault recovery..."
  docker run --rm -it \
    -v "$(pwd)/$VAULT_DIR/:/vault/" \
    --entrypoint="" \
    quantum-secret-vault:latest \
    python3 -m src.cli recover \
    --vault-dir /vault \
    --passphrase "$PASSPHRASE"
else
  # Default to create mode
  SEED="$1"
  PASSPHRASE="$2"
  shift 2
  if [[ -z "$SEED" || -z "$PASSPHRASE" ]]; then
    echo "Usage: ./run.sh create <seed> <passphrase> [layers...]"
    exit 1
  fi
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
    python3 -m src.cli create \
    --seed "$SEED" \
    --passphrase "$PASSPHRASE" \
    $LAYERS \
    --output-dir /output
  echo "Vault created in vault_output/ directory"
fi
