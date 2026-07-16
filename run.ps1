# Quantum Secret Vault - PowerShell Runner
# Usage:
#   .\run.ps1 create "secret text" [password] [layers...]
#   .\run.ps1 recover <vault_dir> [password]
#
# Omit password to be prompted securely (recommended).
# Example:
#   .\run.ps1 create "my secret data" standard_encryption
#   .\run.ps1 recover vault_output

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Mode,
    [Parameter(ValueFromRemainingArguments=$true, Position=1)]
    [string[]]$Args
)

function Test-LayerOrFlag {
    param([string]$Value)
    $layers = @("standard_encryption", "quantum_encryption", "shamir_sharing")
    return ($layers -contains $Value) -or $Value.StartsWith("--")
}

function Get-VaultPassword {
    if ($env:VAULT_PASSWORD) {
        return $env:VAULT_PASSWORD
    }
    $secure = Read-Host "Password" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    if ([string]::IsNullOrEmpty($password)) {
        Write-Host "Error: password cannot be empty"
        exit 1
    }
    return $password
}

# Build the Docker image if needed
Write-Host "Building Docker image..."
docker build -t quantum-secret-vault:latest .

if ($Mode -eq "recover") {
    if ($Args.Count -lt 1) {
        Write-Host "Usage: .\run.ps1 recover <vault_dir> [password] [additional_args...]"
        Write-Host "Omit password to be prompted securely (recommended)."
        exit 1
    }
    $VaultDir = $Args[0]
    $argIndex = 1
    $Password = $null
    if ($Args.Count -gt 1 -and -not (Test-LayerOrFlag $Args[1])) {
        $Password = $Args[1]
        $argIndex = 2
    } else {
        $Password = Get-VaultPassword
    }
    $AdditionalArgs = @()
    if ($Args.Count -gt $argIndex) {
        $AdditionalArgs = $Args[$argIndex..($Args.Count-1)]
    }

    if (-not [System.IO.Path]::IsPathRooted($VaultDir)) {
        $VaultDir = Join-Path (Get-Location) $VaultDir
    }
    if (-not (Test-Path $VaultDir -PathType Container)) {
        Write-Host "Error: vault directory not found: $VaultDir"
        exit 1
    }

    Write-Host "Running vault recovery..."
    if ($AdditionalArgs.Count -gt 0) {
        docker run --rm -it --user root `
          -v "${VaultDir}:/vault/" `
          --entrypoint="" `
          quantum-secret-vault:latest `
          python3 -m src.cli recover `
          --vault-dir /vault `
          --password "$Password" `
          $AdditionalArgs
    } else {
        docker run --rm -it --user root `
          -v "${VaultDir}:/vault/" `
          --entrypoint="" `
          quantum-secret-vault:latest `
          python3 -m src.cli recover `
          --vault-dir /vault `
          --password "$Password"
    }
} else {
    if ($Args.Count -lt 1) {
        Write-Host "Usage: .\run.ps1 create <secret> [password] [layers...]"
        Write-Host "Omit password to be prompted securely (recommended)."
        exit 1
    }
    $Secret = $Args[0]
    $argIndex = 1
    $Password = $null
    if ($Args.Count -gt 1 -and -not (Test-LayerOrFlag $Args[1])) {
        $Password = $Args[1]
        $argIndex = 2
    } else {
        $Password = Get-VaultPassword
    }
    $Layers = @("standard_encryption")
    if ($Args.Count -gt $argIndex) {
        $Layers = $Args[$argIndex..($Args.Count-1)]
    }

    Write-Host "Creating quantum vault with layers: $($Layers -join ' ')"
    Write-Host "Secret: [hidden]"
    Write-Host "Password: [hidden]"
    $VaultOutput = Join-Path $PSScriptRoot "vault_output"
    if (-not (Test-Path $VaultOutput)) {
        New-Item -ItemType Directory -Path $VaultOutput | Out-Null
    }

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
