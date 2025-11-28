# Quantum Secret Vault - PowerShell Runner
# Usage:
#   .\run.ps1 create "secret text" "password" [layers...]
#   .\run.ps1 recover <vault_dir> <password>
# Example:
#   .\run.ps1 create "my secret data" "password" standard_encryption
#   .\run.ps1 recover vault_output "password"

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
        Write-Host "Usage: .\run.ps1 recover <vault_dir> <password> [additional_args...]"
        exit 1
    }
    $VaultDir = $Args[0]
    $Password = $Args[1]
    $AdditionalArgs = @()
    if ($Args.Count -gt 2) {
        $AdditionalArgs = $Args[2..($Args.Count-1)]
    }
    Write-Host "Running vault recovery..."
    if ($AdditionalArgs.Count -gt 0) {
        docker run --rm -it --user root `
          -v "${PWD}/${VaultDir}:/vault/" `
          --entrypoint="" `
          quantum-secret-vault:latest `
          python3 -m src.cli recover `
          --vault-dir /vault `
          --password "$Password" `
          $AdditionalArgs
    } else {
        docker run --rm -it --user root `
          -v "${PWD}/${VaultDir}:/vault/" `
          --entrypoint="" `
          quantum-secret-vault:latest `
          python3 -m src.cli recover `
          --vault-dir /vault `
          --password "$Password"
    }
} else {
    if ($Args.Count -lt 2) {
        Write-Host "Usage: .\run.ps1 create <secret> <password> [layers...]"
        exit 1
    }
    $Secret = $Args[0]
    $Password = $Args[1]
    $Layers = $Args[2..($Args.Count-1)]
    
    Write-Host "Creating quantum vault with layers: $($Layers -join ' ')"
    Write-Host "Secret: [hidden]"
    Write-Host "Password: [hidden]"
    $VaultOutput = Join-Path $PSScriptRoot "vault_output"
    if (-not (Test-Path $VaultOutput)) {
        New-Item -ItemType Directory -Path $VaultOutput | Out-Null
    }
    
    # Build the docker command with layers as single argument - run as root to fix permissions
    $dockerCmd = @(
        "docker", "run", "--rm", "-it", "--user", "root",
        "-v", "${VaultOutput}:/output/",
        "--entrypoint=",
        "quantum-secret-vault:latest",
        "python3", "-m", "src.cli", "create",
        "--secret", "$Secret",
        "--password", "$Password",
        "--layers"
    )
    $dockerCmd += $Layers
    $dockerCmd += "--output-dir", "/output"
    
    & $dockerCmd[0] $dockerCmd[1..($dockerCmd.Count-1)]
    Write-Host "Vault created in vault_output/ directory"
}
