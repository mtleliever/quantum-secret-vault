#!/usr/bin/env bash
# Quantum Secret Vault - Shell Test Runner (macOS / Linux)
# Usage: ./test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Running Quantum Secret Vault tests in Docker..."

echo "Building Docker image..."
docker build -t quantum-secret-vault:latest .

echo "Running tests in Docker container..."
docker run --rm --entrypoint="" quantum-secret-vault:latest python3 run_tests.py

echo "Docker tests completed!"
