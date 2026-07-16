#!/usr/bin/env bash
# Secure Air-Gapped Quantum Vault Workflow (macOS / Linux)
# This script implements maximum security practices for encryption operations
#
# Usage:
#   ./secure_run.sh
#   ./secure_run.sh --force

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FORCE=false
if [[ "${1:-}" == "--force" ]]; then
  FORCE=true
fi

SECURE_TMPDIR="${TMPDIR:-/tmp}/quantum_vault_$$"
DOCKER_IMAGE="quantum-vault-secure:latest"
CONTAINER_NAME="quantum-vault-secure-$$"
SECRET_FILE=""
PASSWORD_FILE=""

# Colors (safe if terminal has no color)
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  RED='\033[0;31m'
  CYAN='\033[0;36m'
  WHITE='\033[0;37m'
  NC='\033[0m'
else
  GREEN='' YELLOW='' RED='' CYAN='' WHITE='' NC=''
fi

secure_wipe_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  if command -v shred >/dev/null 2>&1; then
    shred -u -n 7 "$file" 2>/dev/null || rm -f "$file"
  else
    local size
    size="$(wc -c < "$file" | tr -d ' ')"
    local i
    for i in 1 2 3 4 5 6 7; do
      dd if=/dev/urandom of="$file" bs=1 count="$size" conv=notrunc >/dev/null 2>&1 || true
    done
    rm -f "$file"
  fi
}

cleanup() {
  echo -e "${YELLOW}[CLEANUP] Performing secure cleanup...${NC}"

  if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    echo -e "${GREEN}[CLEANUP] Container removed${NC}"
  fi

  if [[ -d "$SECURE_TMPDIR" ]]; then
    echo -e "${YELLOW}[CLEANUP] Securely wiping temporary files...${NC}"
    while IFS= read -r -d '' file; do
      secure_wipe_file "$file"
    done < <(find "$SECURE_TMPDIR" -type f -print0 2>/dev/null)
    rm -rf "$SECURE_TMPDIR" 2>/dev/null || true
    echo -e "${GREEN}[CLEANUP] Temporary files securely wiped${NC}"
  fi

  # Best-effort: clear sensitive entries from shell history for this session
  history -c 2>/dev/null || true
  echo -e "${GREEN}[CLEANUP] Session history cleared${NC}"
}

trap cleanup EXIT

check_network() {
  echo -e "${CYAN}[SECURITY] Checking network connectivity...${NC}"
  if curl -s --connect-timeout 2 https://1.1.1.1 >/dev/null 2>&1 || \
     curl -s --connect-timeout 2 https://8.8.8.8 >/dev/null 2>&1 || \
     ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    echo -e "${RED}[WARNING] Network connectivity detected!${NC}"
    echo -e "${YELLOW}This script should be run in an air-gapped environment.${NC}"
    if [[ "$FORCE" != "true" ]]; then
      read -r -p "Continue anyway? [y/N] " continue_choice
      if [[ "$continue_choice" != "y" && "$continue_choice" != "Y" ]]; then
        echo -e "${RED}[ABORT] Exiting for security reasons${NC}"
        exit 1
      fi
    fi
  else
    echo -e "${GREEN}[SECURITY] OK - Air-gapped environment confirmed${NC}"
  fi
}

check_docker_image() {
  echo -e "${CYAN}[DOCKER] Checking for pre-built secure image...${NC}"
  if ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] Docker image '$DOCKER_IMAGE' not found${NC}"
    echo -e "${YELLOW}Please build the image first with:${NC}"
    echo "./build_secure_image.sh"
    exit 1
  fi
  echo -e "${GREEN}[DOCKER] OK - Secure image found${NC}"
}

create_secure_tmpdir() {
  echo -e "${CYAN}[SECURITY] Setting up secure temporary directory...${NC}"
  mkdir -p "$SECURE_TMPDIR"
  chmod 700 "$SECURE_TMPDIR"
  echo -e "${GREEN}[SECURITY] OK - Secure tmpdir: $SECURE_TMPDIR${NC}"
}

create_secure_input() {
  local operation="$1"
  SECRET_FILE="${SECURE_TMPDIR}/secret.txt"
  PASSWORD_FILE="${SECURE_TMPDIR}/password.txt"

  echo -e "${CYAN}[INPUT] Creating secure input files...${NC}"

  if [[ "$operation" == "create" ]]; then
    echo -e "${YELLOW}Enter your secret text to encrypt:${NC}"
    read -r -s -p "Secret: " secret_input
    echo
    printf '%s' "$secret_input" > "$SECRET_FILE"
    chmod 600 "$SECRET_FILE"
    unset secret_input
  fi

  echo -e "${YELLOW}Enter your encryption password:${NC}"
  read -r -s -p "Password: " password_input
  echo
  printf '%s' "$password_input" > "$PASSWORD_FILE"
  chmod 600 "$PASSWORD_FILE"
  unset password_input

  echo -e "${GREEN}[INPUT] OK - Secure input files created${NC}"
  if [[ "$operation" == "create" ]]; then
    echo -e "${WHITE}Secret file: $SECRET_FILE${NC}"
  fi
  echo -e "${WHITE}Password file: $PASSWORD_FILE${NC}"
}

run_quantum_vault() {
  local operation="$1"
  local secret_content=""
  local password_content

  password_content="$(cat "$PASSWORD_FILE")"
  if [[ -f "$SECRET_FILE" ]]; then
    secret_content="$(cat "$SECRET_FILE")"
  fi

  echo -e "${CYAN}[VAULT] Running quantum vault operation: $operation${NC}"

  case "$operation" in
    create)
      echo -e "${YELLOW}Select security layers - space-separated:${NC}"
      echo -e "${WHITE}Available: standard_encryption quantum_encryption shamir_sharing${NC}"
      read -r -p "Layers: " layers

      local shamir_args=()
      if [[ "$layers" == *shamir_sharing* ]]; then
        read -r -p "Shamir threshold - e.g. 3: " threshold
        read -r -p "Shamir total - e.g. 5: " total
        shamir_args=(--shamir "$threshold" "$total")
      fi

      echo ""
      echo -e "${CYAN}[SECURITY] Using MAXIMUM Argon2 parameters:${NC}"
      echo -e "${WHITE}  - Memory: 4 GiB (will require 4+ GB RAM)${NC}"
      echo -e "${WHITE}  - Time: 20 iterations${NC}"
      echo -e "${WHITE}  - Threads: 8 parallel${NC}"
      echo -e "${YELLOW}[WARNING] This will take several minutes. Do not interrupt!${NC}"
      echo ""

      # shellcheck disable=SC2086
      docker run --rm --network=none \
        --user root \
        --name "$CONTAINER_NAME" \
        -v "${SECURE_TMPDIR}:/secure" \
        "$DOCKER_IMAGE" \
        python3 -m src.cli create \
        --secret "$secret_content" \
        --password "$password_content" \
        --memory 4194304 \
        --time 20 \
        --threads 8 \
        --layers $layers \
        --output-dir /secure/vault_output \
        "${shamir_args[@]}"
      ;;
    recover)
      echo -e "${YELLOW}Enter the full path to your vault directory:${NC}"
      echo -e "${WHITE}Example: /Users/you/path/to/vault_output${NC}"
      read -r -p "Vault path: " vault_path

      if [[ ! -d "$vault_path" ]]; then
        echo -e "${RED}[ERROR] Vault directory not found: $vault_path${NC}"
        exit 1
      fi

      docker run --rm --network=none \
        --user root \
        --name "$CONTAINER_NAME" \
        -v "${vault_path}:/vault:ro" \
        -v "${SECURE_TMPDIR}:/secure" \
        "$DOCKER_IMAGE" \
        python3 -m src.cli recover \
        --vault-dir /vault \
        --password "$password_content"
      ;;
    *)
      echo -e "${RED}[ERROR] Unknown operation: $operation${NC}"
      exit 1
      ;;
  esac

  unset secret_content password_content
}

wipe_secure_input() {
  echo -e "${CYAN}[SECURITY] Performing secure wipe of input files...${NC}"
  if [[ -n "$SECRET_FILE" && -f "$SECRET_FILE" ]]; then
    secure_wipe_file "$SECRET_FILE"
    echo -e "${GREEN}[SECURITY] OK - secret.txt securely wiped${NC}"
  fi
  if [[ -n "$PASSWORD_FILE" && -f "$PASSWORD_FILE" ]]; then
    secure_wipe_file "$PASSWORD_FILE"
    echo -e "${GREEN}[SECURITY] OK - password.txt securely wiped${NC}"
  fi
}

main() {
  echo -e "${GREEN}=== SECURE QUANTUM VAULT WORKFLOW ===${NC}"
  echo -e "${YELLOW}Maximum security air-gapped encryption operations${NC}"
  echo ""

  check_network
  check_docker_image
  create_secure_tmpdir

  echo -e "${CYAN}[OPERATION] Select operation:${NC}"
  echo -e "${WHITE}1 - Create vault${NC}"
  echo -e "${WHITE}2 - Recover vault${NC}"
  read -r -p "Choice [1-2]: " choice

  local operation
  case "$choice" in
    1) operation="create" ;;
    2) operation="recover" ;;
    *)
      echo -e "${RED}[ERROR] Invalid choice${NC}"
      exit 1
      ;;
  esac

  create_secure_input "$operation"

  run_quantum_vault "$operation"
  echo -e "${GREEN}[SUCCESS] Operation completed securely${NC}"

  local vault_output_dir="${SECURE_TMPDIR}/vault_output"
  if [[ -d "$vault_output_dir" ]]; then
    local permanent_dir="${PWD}/vault_output"
    echo ""
    echo -e "${YELLOW}[SAVE] Vault files need to be saved before cleanup.${NC}"
    echo -e "${WHITE}Default location: $permanent_dir${NC}"
    read -r -p "Press Enter to use default, or enter custom path: " custom_path

    if [[ -n "$custom_path" ]]; then
      permanent_dir="$custom_path"
    fi

    mkdir -p "$permanent_dir"
    cp -R "${vault_output_dir}/." "$permanent_dir/"

    echo -e "${GREEN}[SAVE] OK - Vault files saved to: $permanent_dir${NC}"
    echo ""
    echo -e "${CYAN}[IMPORTANT] Your vault files are in: $permanent_dir${NC}"
    echo -e "${WHITE}[SAVED] Files:${NC}"
    find "$permanent_dir" -type f | while read -r f; do
      echo -e "  - $f"
    done
  fi

  echo ""
  echo -e "${YELLOW}[REMINDER] Distribute Shamir shares to different secure locations!${NC}"

  wipe_secure_input
}

main
