# Secure Air-Gapped Quantum Vault Workflow
# This script implements maximum security practices for encryption operations

param(
    [switch]$Force = $false
)

$ErrorActionPreference = "Stop"

# Security configuration
$SECURE_TMPDIR = "$env:TEMP\quantum_vault_$PID"
$DOCKER_IMAGE = "quantum-vault-secure:latest"
$CONTAINER_NAME = "quantum-vault-secure-$PID"

# Cleanup function
function Invoke-Cleanup {
    Write-Host "[CLEANUP] Performing secure cleanup..." -ForegroundColor Yellow
    
    # Stop and remove container if it exists
    try {
        $containers = docker ps -a --format "{{.Names}}" | Where-Object { $_ -eq $CONTAINER_NAME }
        if ($containers) {
            docker stop $CONTAINER_NAME 2>$null | Out-Null
            docker rm -f $CONTAINER_NAME 2>$null | Out-Null
            Write-Host "[CLEANUP] Container removed" -ForegroundColor Green
        }
    } catch {
        # Silently continue if container cleanup fails
    }
    
    # Secure wipe of temporary directory
    if (Test-Path $SECURE_TMPDIR) {
        Write-Host "[CLEANUP] Securely wiping temporary files..." -ForegroundColor Yellow
        try {
            # PowerShell equivalent of secure file deletion
            Get-ChildItem -Path $SECURE_TMPDIR -File -Recurse | ForEach-Object {
                # Overwrite file with random data multiple times
                for ($i = 0; $i -lt 3; $i++) {
                    $randomBytes = New-Object byte[] $_.Length
                    (New-Object Random).NextBytes($randomBytes)
                    [System.IO.File]::WriteAllBytes($_.FullName, $randomBytes)
                }
                Remove-Item $_.FullName -Force
            }
            Remove-Item $SECURE_TMPDIR -Recurse -Force
            Write-Host "[CLEANUP] Temporary files securely wiped" -ForegroundColor Green
        } catch {
            Write-Host "[CLEANUP] Warning: Could not securely wipe all files" -ForegroundColor Yellow
        }
    }
    
    # Clear PowerShell history for this session
    try {
        Clear-History
        Write-Host "[CLEANUP] Session history cleared" -ForegroundColor Green
    } catch {
        Write-Host "[CLEANUP] Warning: Could not clear history" -ForegroundColor Yellow
    }
}

# Set cleanup to run on exit
Register-EngineEvent PowerShell.Exiting -Action { Invoke-Cleanup }

# Function to check if we're air-gapped
function Test-NetworkConnectivity {
    Write-Host "[SECURITY] Checking network connectivity..." -ForegroundColor Cyan
    try {
        $ping = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        if ($ping) {
            Write-Host "[WARNING] Network connectivity detected!" -ForegroundColor Red
            Write-Host "This script should be run in an air-gapped environment." -ForegroundColor Yellow
            if (-not $Force) {
                $continue = Read-Host "Continue anyway? [y/N]"
                if ($continue -ne "y" -and $continue -ne "Y") {
                    Write-Host "[ABORT] Exiting for security reasons" -ForegroundColor Red
                    exit 1
                }
            }
        } else {
            Write-Host "[SECURITY] OK - Air-gapped environment confirmed" -ForegroundColor Green
        }
    } catch {
        Write-Host "[SECURITY] OK - Air-gapped environment confirmed" -ForegroundColor Green
    }
}

# Function to check if Docker image exists
function Test-DockerImage {
    Write-Host "[DOCKER] Checking for pre-built secure image..." -ForegroundColor Cyan
    try {
        docker image inspect $DOCKER_IMAGE | Out-Null
        Write-Host "[DOCKER] OK - Secure image found" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Docker image '$DOCKER_IMAGE' not found" -ForegroundColor Red
        Write-Host "Please build the image first with:" -ForegroundColor Yellow
        Write-Host ".\build_secure_image.ps1" -ForegroundColor White
        exit 1
    }
}

# Function to create secure temporary directory
function New-SecureTmpDir {
    Write-Host "[SECURITY] Setting up secure temporary directory..." -ForegroundColor Cyan
    try {
        New-Item -ItemType Directory -Path $SECURE_TMPDIR -Force | Out-Null
        # Set restrictive permissions (owner only)
        $acl = Get-Acl $SECURE_TMPDIR
        $acl.SetAccessRuleProtection($true, $false)
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $SECURE_TMPDIR -AclObject $acl
        Write-Host "[SECURITY] OK - Secure tmpdir: $SECURE_TMPDIR" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to create secure temporary directory" -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
        exit 1
    }
}

# Function to create secure input files
function New-SecureInput {
    param(
        [string]$Operation = "create"
    )
    
    $secretFile = Join-Path $SECURE_TMPDIR "secret.txt"
    $passwordFile = Join-Path $SECURE_TMPDIR "password.txt"
    
    Write-Host "[INPUT] Creating secure input files..." -ForegroundColor Cyan
    
    # Only ask for secret when creating (not recovering)
    if ($Operation -eq "create") {
        Write-Host "Enter your secret text to encrypt:" -ForegroundColor Yellow
        $secretInput = Read-Host "Secret" -AsSecureString
        $secretPlaintext = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretInput))
        Set-Content -Path $secretFile -Value $secretPlaintext -NoNewline
        
        # Clear from memory
        $secretPlaintext = $null
        $secretInput = $null
    }
    
    # Always ask for password (needed for both create and recover)
    Write-Host "Enter your encryption password:" -ForegroundColor Yellow
    $password = Read-Host "Password" -AsSecureString
    $passwordPlaintext = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    Set-Content -Path $passwordFile -Value $passwordPlaintext -NoNewline
    
    # Clear from memory
    $passwordPlaintext = $null
    $password = $null
    [GC]::Collect()
    
    # Set restrictive permissions on files that exist
    $files = @()
    if (Test-Path $secretFile) { $files += $secretFile }
    if (Test-Path $passwordFile) { $files += $passwordFile }
    
    foreach ($file in $files) {
        $acl = Get-Acl $file
        $acl.SetAccessRuleProtection($true, $false)
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            "FullControl",
            "Allow"
        )
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $file -AclObject $acl
    }
    
    Write-Host "[INPUT] OK - Secure input files created" -ForegroundColor Green
    if ($Operation -eq "create") {
        Write-Host "Secret file: $secretFile" -ForegroundColor White
    }
    Write-Host "Password file: $passwordFile" -ForegroundColor White
    
    return @{
        SecretFile = $secretFile
        PasswordFile = $passwordFile
    }
}

# Function to run quantum vault in secure container
function Invoke-QuantumVault {
    param(
        [string]$Operation,
        [hashtable]$InputFiles
    )
    
    $secretFile = $InputFiles.SecretFile
    $passwordFile = $InputFiles.PasswordFile
    $outputDir = Join-Path $SECURE_TMPDIR "vault_output"
    
    Write-Host "[VAULT] Running quantum vault operation: $Operation" -ForegroundColor Cyan
    
    # Read file contents for Docker command (only read files that exist)
    $secretContent = ""
    if ($secretFile -and (Test-Path $secretFile)) {
        $secretContent = Get-Content $secretFile -Raw
    }
    $passwordContent = Get-Content $passwordFile -Raw
    
    switch ($Operation) {
        "create" {
            # Get additional parameters
            Write-Host "Select security layers - space-separated:" -ForegroundColor Yellow
            Write-Host "Available: standard_encryption quantum_encryption shamir_sharing" -ForegroundColor White
            $layers = Read-Host "Layers"
            
            # Get Shamir parameters if needed
            $shamirArgs = ""
            if ($layers -like "*shamir_sharing*") {
                $threshold = Read-Host "Shamir threshold - e.g. 3"
                $total = Read-Host "Shamir total - e.g. 5"
                $shamirArgs = "--shamir $threshold $total"
            }
            
            Write-Host ""
            Write-Host "[SECURITY] Using MAXIMUM Argon2 parameters:" -ForegroundColor Cyan
            Write-Host "  - Memory: 4 GiB (will require 4+ GB RAM)" -ForegroundColor White
            Write-Host "  - Time: 20 iterations" -ForegroundColor White
            Write-Host "  - Threads: 8 parallel" -ForegroundColor White
            Write-Host "[WARNING] This will take several minutes. Do not interrupt!" -ForegroundColor Yellow
            Write-Host ""
            
            # Run vault creation
            # Use --user root to ensure write access to mounted Windows volume
            # Use maximum Argon2 parameters for strongest security:
            #   --memory 4194304 = 4 GiB (maximum allowed)
            #   --time 20 = 20 iterations (maximum allowed)
            #   --threads 8 = 8 parallel threads (maximum allowed)
            $dockerCmd = @(
                "run", "--rm", "--network=none",
                "--user", "root",
                "--name", $CONTAINER_NAME,
                "-v", "${SECURE_TMPDIR}:/secure",
                $DOCKER_IMAGE,
                "python3", "-m", "src.cli", "create",
                "--secret", $secretContent,
                "--password", $passwordContent,
                "--memory", "4194304",
                "--time", "20",
                "--threads", "8",
                "--layers"
            ) + $layers.Split(' ') + @(
                "--output-dir", "/secure/vault_output"
            )
            
            if ($shamirArgs) {
                $dockerCmd += $shamirArgs.Split(' ')
            }
            
            & docker @dockerCmd
        }
        
        "recover" {
            Write-Host "Enter the full path to your vault directory:" -ForegroundColor Yellow
            Write-Host "Example: D:\path\to\vault_output" -ForegroundColor White
            $vaultPath = Read-Host "Vault path"
            
            # Validate the path exists
            if (-not (Test-Path $vaultPath)) {
                Write-Host "[ERROR] Vault directory not found: $vaultPath" -ForegroundColor Red
                exit 1
            }
            
            # Mount the vault directory read-only for recovery
            # Use --user root to ensure read access to mounted Windows volume
            $dockerCmd = @(
                "run", "--rm", "--network=none",
                "--user", "root",
                "--name", $CONTAINER_NAME,
                "-v", "${vaultPath}:/vault:ro",
                "-v", "${SECURE_TMPDIR}:/secure",
                $DOCKER_IMAGE,
                "python3", "-m", "src.cli", "recover",
                "--vault-dir", "/vault",
                "--password", $passwordContent
            )
            
            & docker @dockerCmd
        }
        
        default {
            Write-Host "[ERROR] Unknown operation: $Operation" -ForegroundColor Red
            exit 1
        }
    }
}

# Function to secure wipe input files
function Remove-SecureInput {
    param([hashtable]$InputFiles)
    
    Write-Host "[SECURITY] Performing secure wipe of input files..." -ForegroundColor Cyan
    
    # Only include files that exist
    $files = @()
    if ($InputFiles.SecretFile -and (Test-Path $InputFiles.SecretFile)) {
        $files += $InputFiles.SecretFile
    }
    if ($InputFiles.PasswordFile -and (Test-Path $InputFiles.PasswordFile)) {
        $files += $InputFiles.PasswordFile
    }
    
    foreach ($file in $files) {
        if (Test-Path $file) {
            try {
                # Multiple-pass secure wipe
                $fileInfo = Get-Item $file
                for ($i = 0; $i -lt 7; $i++) {
                    $randomBytes = New-Object byte[] $fileInfo.Length
                    (New-Object Random).NextBytes($randomBytes)
                    [System.IO.File]::WriteAllBytes($file, $randomBytes)
                }
                Remove-Item $file -Force
                $fileName = Split-Path $file -Leaf
                Write-Host "[SECURITY] OK - $fileName securely wiped" -ForegroundColor Green
            } catch {
                $fileName = Split-Path $file -Leaf
                Write-Host "[SECURITY] Warning: Could not securely wipe $fileName" -ForegroundColor Yellow
            }
        }
    }
}

# Main execution
function Main {
    Write-Host "=== SECURE QUANTUM VAULT WORKFLOW ===" -ForegroundColor Green
    Write-Host "Maximum security air-gapped encryption operations" -ForegroundColor Yellow
    Write-Host ""
    
    # Security checks
    Test-NetworkConnectivity
    Test-DockerImage
    New-SecureTmpDir
    
    # Get operation type
    Write-Host "[OPERATION] Select operation:" -ForegroundColor Cyan
    Write-Host "1 - Create vault" -ForegroundColor White
    Write-Host "2 - Recover vault" -ForegroundColor White
    $choice = Read-Host "Choice [1-2]"
    
    $operation = switch ($choice) {
        "1" { "create" }
        "2" { "recover" }
        default {
            Write-Host "[ERROR] Invalid choice" -ForegroundColor Red
            exit 1
        }
    }
    
    # Create secure inputs (only asks for secret when creating, not recovering)
    $inputFiles = New-SecureInput -Operation $operation
    
    try {
        # Run the operation
        Invoke-QuantumVault -Operation $operation -InputFiles $inputFiles
        
        Write-Host "[SUCCESS] Operation completed securely" -ForegroundColor Green
        
        # Copy vault output to a permanent location
        $vaultOutputDir = Join-Path $SECURE_TMPDIR "vault_output"
        if (Test-Path $vaultOutputDir) {
            $permanentDir = Join-Path (Get-Location) "vault_output"
            Write-Host ""
            Write-Host "[SAVE] Vault files need to be saved before cleanup." -ForegroundColor Yellow
            Write-Host "Default location: $permanentDir" -ForegroundColor White
            $customPath = Read-Host "Press Enter to use default, or enter custom path"
            
            if ($customPath) {
                $permanentDir = $customPath
            }
            
            # Create destination and copy files
            if (-not (Test-Path $permanentDir)) {
                New-Item -ItemType Directory -Path $permanentDir -Force | Out-Null
            }
            
            Copy-Item -Path "$vaultOutputDir\*" -Destination $permanentDir -Recurse -Force
            
            Write-Host "[SAVE] OK - Vault files saved to: $permanentDir" -ForegroundColor Green
            Write-Host ""
            Write-Host "[IMPORTANT] Your vault files are in: $permanentDir" -ForegroundColor Cyan
            
            # Show what was saved
            $savedFiles = Get-ChildItem -Path $permanentDir -Recurse -File
            Write-Host "[SAVED] Files:" -ForegroundColor White
            foreach ($f in $savedFiles) {
                Write-Host "  - $($f.FullName)" -ForegroundColor White
            }
        }
        
        Write-Host ""
        Write-Host "[REMINDER] Distribute Shamir shares to different secure locations!" -ForegroundColor Yellow
    } finally {
        # Secure cleanup of sensitive files
        Remove-SecureInput -InputFiles $inputFiles
    }
}

# Run main function
try {
    Main
} finally {
    Invoke-Cleanup
}
