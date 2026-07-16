#!/usr/bin/env bash
# Build Secure Quantum Vault Docker Image (macOS / Linux)
# Run this BEFORE going air-gapped
#
# Usage:
#   ./build_secure_image.sh
#   ./build_secure_image.sh --skip-scan

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SKIP_SCAN=false
if [[ "${1:-}" == "--skip-scan" ]]; then
  SKIP_SCAN=true
fi

DOCKER_IMAGE="quantum-vault-secure:latest"

echo "=== BUILDING SECURE QUANTUM VAULT IMAGE ==="
echo "This should be run BEFORE going air-gapped"
echo ""

echo "[CHECK] Verifying internet connectivity..."
if ! curl -s --connect-timeout 3 https://1.1.1.1 >/dev/null 2>&1 && \
   ! curl -s --connect-timeout 3 https://8.8.8.8 >/dev/null 2>&1 && \
   ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
  echo "[ERROR] No internet connectivity detected"
  echo "This script needs internet to download dependencies"
  exit 1
fi
echo "[CHECK] OK - Internet connectivity confirmed"

if [[ ! -f "dockerfile" ]]; then
  echo "[ERROR] dockerfile not found"
  echo "Please run this script from the quantum-secret-vault directory"
  exit 1
fi

echo "[VERIFY] Checking for placeholder commit hashes..."
if grep -Eq "4c0c4b8b6c8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e|1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b" dockerfile; then
  echo "[WARNING] Placeholder commit hashes detected in Dockerfile"
  echo "Please replace with real commit hashes for maximum security"
  echo "Run: ./get_commit_hashes.sh (or get_commit_hashes.ps1) to get real hashes"
  read -r -p "Continue with placeholders? (y/N) " continue_choice
  if [[ "$continue_choice" != "y" && "$continue_choice" != "Y" ]]; then
    echo "[ABORT] Please update commit hashes first"
    exit 1
  fi
fi

echo "[BUILD] Building secure Docker image..."
echo "This may take several minutes..."

if ! docker build -t "$DOCKER_IMAGE" -f dockerfile .; then
  echo "[BUILD] FAILED - Docker image build failed"
  exit 1
fi
echo "[BUILD] OK - Docker image built successfully"

echo "[VERIFY] Verifying image creation..."
if ! image_json="$(docker image inspect "$DOCKER_IMAGE" 2>/dev/null)"; then
  echo "[VERIFY] FAILED - Image verification failed"
  exit 1
fi
echo "[VERIFY] OK - Image verified: $DOCKER_IMAGE"

echo "[INFO] Image details:"
image_id="$(echo "$image_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["Id"][7:19])' 2>/dev/null || echo "unknown")"
image_size="$(echo "$image_json" | python3 -c 'import json,sys; print(round(json.load(sys.stdin)[0]["Size"] / (1024**3), 2))' 2>/dev/null || echo "unknown")"
echo "  Image ID: $image_id"
echo "  Size: ${image_size} GB"

if [[ "$SKIP_SCAN" != "true" ]]; then
  echo "[SECURITY] Run security scan? (recommended)"
  read -r -p "Scan image for vulnerabilities? (Y/n) " scan_choice
  if [[ -z "$scan_choice" || "$scan_choice" == "Y" || "$scan_choice" == "y" ]]; then
    echo "[SCAN] Running security scan..."
    if command -v trivy >/dev/null 2>&1; then
      trivy image "$DOCKER_IMAGE" || echo "[SCAN] Security scan failed, but continuing..."
    else
      echo "[SCAN] Trivy not found, using Docker Hub scanner..."
      docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        aquasec/trivy:latest image "$DOCKER_IMAGE" || \
        echo "[SCAN] Security scan failed, but continuing..."
    fi
  fi
fi

echo ""
echo "=== BUILD COMPLETE ==="
echo "[OK] Secure image ready: $DOCKER_IMAGE"
echo ""
echo "Next steps:"
echo "1. Disconnect from internet (air-gap your system)"
echo "2. Run: ./secure_run.sh"
echo "3. After operations, reconnect to internet"
echo ""
echo "[SECURITY] Remember to:"
echo "- Use a dedicated, offline machine for sensitive operations"
echo "- Never run this on shared or cloud systems"
echo "- Physically disconnect network cables (or disable Wi-Fi)"
