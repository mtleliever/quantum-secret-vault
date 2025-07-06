# Quantum Secret Vault - PowerShell Runner
# Usage:
#   .\run.ps1 create "seed phrase" "passphrase" [layers...]
#   .\run.ps1 recover <vault_dir> <passphrase>
# Example:
#   .\run.ps1 create "word1 ... word24" "passphrase" standard_encryption
#   .\run.ps1 recover vault_output "passphrase"

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Mode,
    [Parameter(ValueFromRemainingArguments=$true, Position=1)]
    [string[]]$Args
)

# Build the Docker image if needed
Write-Host "Building Docker image..."
docker build -t quantum-secret-vault:latest .

if ($Mode -eq "recover") {
    if ($Args.Count -lt 2) {
        Write-Host "Usage: .\run.ps1 recover <vault_dir> <passphrase>"
        exit 1
    }
    $VaultDir = $Args[0]
    $Passphrase = $Args[1]
    Write-Host "Running vault recovery..."
    docker run --rm -it `
      -v "${PWD}/${VaultDir}:/vault/" `
      --entrypoint="" `
      quantum-secret-vault:latest `
      python3 -m src.cli recover `
      --vault-dir /vault `
      --passphrase "$Passphrase"
} else {
    if ($Args.Count -lt 2) {
        Write-Host "Usage: .\run.ps1 create <seed> <passphrase> [layers...]"
        exit 1
    }
    $Seed = $Args[0]
    $Passphrase = $Args[1]
    $Layers = $Args[2..($Args.Count-1)]
    $layersArg = @()
    foreach ($layer in $Layers) {
        $layersArg += @('--layers', $layer)
    }
    Write-Host "Creating quantum vault with layers: $($Layers -join ' ')"
    Write-Host "Seed: $Seed"
    Write-Host "Passphrase: $Passphrase"
    $VaultOutput = Join-Path $PSScriptRoot "vault_output"
    if (-not (Test-Path $VaultOutput)) {
        New-Item -ItemType Directory -Path $VaultOutput | Out-Null
    }
    docker run --rm -it `
      -v "${VaultOutput}:/output/" `
      --entrypoint="" `
      quantum-secret-vault:latest `
      python3 -m src.cli create `
      --seed "$Seed" `
      --passphrase "$Passphrase" `
      @layersArg `
      --output-dir /output
    Write-Host "Vault created in vault_output/ directory"
} 