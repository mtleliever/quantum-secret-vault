#!/usr/bin/env bash
# Quantum Secret Vault - Shell Runner (macOS / Linux)
# Usage:
#   ./run.sh create "secret text" [password] [layers...]
#   ./run.sh recover <vault_dir> [password]
#
# Password is optional. If omitted (or set via VAULT_PASSWORD), you will be
# prompted securely so it never appears in shell history.
#
# Example:
#   ./run.sh create "my secret data" standard_encryption
#   ./run.sh recover ~/Downloads/vaults/mitchell/vault_1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LAYER_NAMES="standard_encryption|quantum_encryption|shamir_sharing"

prompt_password() {
  local password=""
  if [[ -n "${VAULT_PASSWORD:-}" ]]; then
    password="$VAULT_PASSWORD"
  else
    read -r -s -p "Password: " password
    echo >&2
    if [[ -z "$password" ]]; then
      echo "Error: password cannot be empty" >&2
      exit 1
    fi
  fi
  printf '%s' "$password"
}

is_layer_or_flag() {
  [[ "$1" =~ ^($LAYER_NAMES)$ ]] || [[ "$1" == --* ]]
}

if [[ $# -lt 1 ]]; then
  echo "Usage:"
  echo "  ./run.sh create <secret> [password] [layers...]"
  echo "  ./run.sh recover <vault_dir> [password] [additional_args...]"
  echo ""
  echo "Omit password to be prompted securely (recommended)."
  exit 1
fi

MODE="$1"
shift

echo "Building Docker image..."
docker build -t quantum-secret-vault:latest .

if [[ "$MODE" == "recover" ]]; then
  if [[ $# -lt 1 ]]; then
    echo "Usage: ./run.sh recover <vault_dir> [password] [additional_args...]"
    exit 1
  fi
  VAULT_DIR="$1"
  shift

  PASSWORD=""
  if [[ $# -ge 1 ]] && ! is_layer_or_flag "$1"; then
    PASSWORD="$1"
    shift
  else
    PASSWORD="$(prompt_password)"
  fi

  # Support absolute paths and ~; otherwise resolve relative to the repo
  if [[ "$VAULT_DIR" != /* ]]; then
    VAULT_DIR="${PWD}/${VAULT_DIR}"
  fi
  if [[ ! -d "$VAULT_DIR" ]]; then
    echo "Error: vault directory not found: $VAULT_DIR"
    exit 1
  fi

  echo "Running vault recovery..."
  docker run --rm -it --user root \
    -v "${VAULT_DIR}:/vault/" \
    --entrypoint="" \
    quantum-secret-vault:latest \
    python3 -m src.cli recover \
    --vault-dir /vault \
    --password "$PASSWORD" \
    "$@"
else
  if [[ $# -lt 1 ]]; then
    echo "Usage: ./run.sh create <secret> [password] [layers...]"
    exit 1
  fi
  SECRET="$1"
  shift

  PASSWORD=""
  if [[ $# -ge 1 ]] && ! is_layer_or_flag "$1"; then
    PASSWORD="$1"
    shift
  else
    PASSWORD="$(prompt_password)"
  fi

  if [[ $# -eq 0 ]]; then
    set -- standard_encryption
  fi

  echo "Creating quantum vault with layers: $*"
  echo "Secret: [hidden]"
  echo "Password: [hidden]"

  VAULT_OUTPUT="${SCRIPT_DIR}/vault_output"
  mkdir -p "$VAULT_OUTPUT"

  docker run --rm -it --user root \
    -v "${VAULT_OUTPUT}:/output/" \
    --entrypoint="" \
    quantum-secret-vault:latest \
    python3 -m src.cli create \
    --secret "$SECRET" \
    --password "$PASSWORD" \
    --layers "$@" \
    --output-dir /output

  echo "Vault created in vault_output/ directory"
fi
