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
  shift 2
  ADDITIONAL_ARGS="$@"
  if [[ -z "$VAULT_DIR" || -z "$PASSPHRASE" ]]; then
    echo "Usage: ./run.sh recover <vault_dir> <passphrase> [additional_args...]"
    exit 1
  fi
  echo "Running vault recovery..."
  if [[ -n "$ADDITIONAL_ARGS" ]]; then
    docker run --rm -it \
      -v "$(pwd)/$VAULT_DIR/:/vault/" \
      --entrypoint="" \
      quantum-secret-vault:latest \
      python3 -m src.cli recover \
      --vault-dir /vault \
      --passphrase "$PASSPHRASE" \
      $ADDITIONAL_ARGS
  else
    docker run --rm -it \
      -v "$(pwd)/$VAULT_DIR/:/vault/" \
      --entrypoint="" \
      quantum-secret-vault:latest \
      python3 -m src.cli recover \
      --vault-dir /vault \
      --passphrase "$PASSPHRASE"
  fi
else
  # Default to create mode
  SEED="$1"
  PASSPHRASE="$2"
  shift 2
  if [[ -z "$SEED" || -z "$PASSPHRASE" ]]; then
    echo "Usage: ./run.sh create <seed> <passphrase> [layers...]"
    exit 1
  fi
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
    --layers "$@" \
    --output-dir /output
  echo "Vault created in vault_output/ directory"
fi
