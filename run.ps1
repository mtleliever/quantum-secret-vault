# Quantum Secret Vault - PowerShell Runner
# Usage: .\run.ps1 "seed phrase" "passphrase" [layers...]
# Example: .\run.ps1 "word1 ... word24" "passphrase" standard_encryption
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Seed,
    [Parameter(Mandatory=$true, Position=1)]
    [string]$Passphrase,
    [Parameter(ValueFromRemainingArguments=$true, Position=2)]
    [string[]]$Layers
)

# Build the Docker image
Write-Host "Building Docker image..."
docker build -t quantum-secret-vault:latest .

# Run the vault creation
Write-Host "Running vault creation..."

# Set the absolute path for vault_output
$VaultOutput = Join-Path $PSScriptRoot "vault_output"

# Build layers argument as an array
$layersArg = @()
foreach ($layer in $Layers) {
    $layersArg += @('--layers', $layer)
}

Write-Host "Creating quantum vault with layers: $($Layers -join ' ')"
Write-Host "Seed: $Seed"
Write-Host "Passphrase: $Passphrase"

# Create output directory if it doesn't exist
if (-not (Test-Path $VaultOutput)) {
    New-Item -ItemType Directory -Path $VaultOutput | Out-Null
}

# Run the vault creation directly with Python (bypassing entrypoint)
docker run --rm -it `
  -v "${VaultOutput}:/output/" `
  --entrypoint="" `
  quantum-secret-vault:latest `
  python3 -m src.cli `
  --seed "$Seed" `
  --passphrase "$Passphrase" `
  @layersArg `
  --output-dir /output

Write-Host "Vault created in vault_output/ directory" 