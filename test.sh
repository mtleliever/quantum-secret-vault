#!/bin/bash
# Docker test script for Quantum Secret Vault

set -e

echo "🐳 Running Quantum Secret Vault tests in Docker..."

# Build the Docker image
echo "📦 Building Docker image..."
docker build -t quantum-secret-vault:latest .

# Run tests in container (bypass entrypoint)
echo "🧪 Running tests in Docker container..."
docker run --rm --entrypoint="" quantum-secret-vault:latest python3 run_tests.py

echo "✅ Docker tests completed!" 