# Quantum Secret Vault - PowerShell Test Runner
# Usage: .\test.ps1

# Set the absolute path for tests and output
Write-Host "Running Quantum Secret Vault tests in Docker..."

# Build the Docker image
Write-Host "Building Docker image..."
docker build -t quantum-secret-vault:latest .

Write-Host "Running tests in Docker container..."
docker run --rm --entrypoint="" quantum-secret-vault:latest python3 run_tests.py

Write-Host "Docker tests completed!" 