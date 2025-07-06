# Quantum Secret Vault - PowerShell Test Runner
# Usage: .\test.ps1

# Set the absolute path for tests and output
$TestDir = Join-Path $PSScriptRoot "tests"
$SrcDir = Join-Path $PSScriptRoot "src"

Write-Host "Running test suite in Docker..."

docker run --rm --entrypoint="" quantum-secret-vault:latest python3 run_tests.py