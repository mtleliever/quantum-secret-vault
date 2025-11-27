# Build Secure Quantum Vault Docker Image
# Run this BEFORE going air-gapped

param(
    [switch]$SkipScan = $false
)

$ErrorActionPreference = "Stop"

$DOCKER_IMAGE = "quantum-vault-secure:latest"

Write-Host "=== BUILDING SECURE QUANTUM VAULT IMAGE ===" -ForegroundColor Green
Write-Host "This should be run BEFORE going air-gapped" -ForegroundColor Yellow
Write-Host ""

# Check if we have internet connectivity
Write-Host "[CHECK] Verifying internet connectivity..." -ForegroundColor Cyan
try {
    $ping = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue
    if (-not $ping) {
        throw "No connectivity"
    }
    Write-Host "[CHECK] OK - Internet connectivity confirmed" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] No internet connectivity detected" -ForegroundColor Red
    Write-Host "This script needs internet to download dependencies" -ForegroundColor Yellow
    exit 1
}

# Check if Dockerfile exists
if (-not (Test-Path "dockerfile")) {
    Write-Host "[ERROR] dockerfile not found" -ForegroundColor Red
    Write-Host "Please run this script from the quantum-secret-vault directory" -ForegroundColor Yellow
    exit 1
}

# Verify commit hashes in Dockerfile are not placeholders
Write-Host "[VERIFY] Checking for placeholder commit hashes..." -ForegroundColor Cyan
$dockerfileContent = Get-Content "dockerfile" -Raw
if ($dockerfileContent -match "4c0c4b8b6c8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e|1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b") {
    Write-Host "[WARNING] Placeholder commit hashes detected in Dockerfile" -ForegroundColor Red
    Write-Host "Please replace with real commit hashes for maximum security" -ForegroundColor Yellow
    Write-Host "Run: .\get_commit_hashes.ps1 to get real hashes" -ForegroundColor Yellow
    $continue = Read-Host "Continue with placeholders? (y/N)"
    if ($continue -ne "y" -and $continue -ne "Y") {
        Write-Host "[ABORT] Please update commit hashes first" -ForegroundColor Red
        exit 1
    }
}

# Build the secure Docker image
Write-Host "[BUILD] Building secure Docker image..." -ForegroundColor Cyan
Write-Host "This may take several minutes..." -ForegroundColor Yellow

try {
    docker build -t $DOCKER_IMAGE -f dockerfile .
    if ($LASTEXITCODE -ne 0) {
        throw "Docker build failed"
    }
    Write-Host "[BUILD] OK - Docker image built successfully" -ForegroundColor Green
} catch {
    Write-Host "[BUILD] FAILED - Docker image build failed" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}

# Verify the image was created
Write-Host "[VERIFY] Verifying image creation..." -ForegroundColor Cyan
try {
    $imageInfo = docker image inspect $DOCKER_IMAGE | ConvertFrom-Json
    Write-Host "[VERIFY] OK - Image verified: $DOCKER_IMAGE" -ForegroundColor Green
    
    # Show image details
    Write-Host "[INFO] Image details:" -ForegroundColor Cyan
    $imageId = $imageInfo[0].Id.Substring(7, 12)  # Remove 'sha256:' prefix and take first 12 chars
    Write-Host "  Image ID: $imageId" -ForegroundColor White
    $sizeGB = [math]::Round($imageInfo[0].Size / 1GB, 2)
    Write-Host "  Size: $sizeGB GB" -ForegroundColor White
} catch {
    Write-Host "[VERIFY] FAILED - Image verification failed" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}

# Optional: Run security scan
if (-not $SkipScan) {
    Write-Host "[SECURITY] Run security scan? (recommended)" -ForegroundColor Cyan
    $scanChoice = Read-Host "Scan image for vulnerabilities? (Y/n)"
    if ($scanChoice -eq "" -or $scanChoice -eq "Y" -or $scanChoice -eq "y") {
        Write-Host "[SCAN] Running security scan..." -ForegroundColor Cyan
        try {
            # Check if trivy is available
            $trivyPath = Get-Command trivy -ErrorAction SilentlyContinue
            if ($trivyPath) {
                trivy image $DOCKER_IMAGE
            } else {
                Write-Host "[SCAN] Trivy not found, using Docker Hub scanner..." -ForegroundColor Yellow
                docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image $DOCKER_IMAGE
            }
        } catch {
            Write-Host "[SCAN] Security scan failed, but continuing..." -ForegroundColor Yellow
            Write-Host "Error: $_" -ForegroundColor Yellow
        }
    }
}

# Success message
Write-Host ""
Write-Host "=== BUILD COMPLETE ===" -ForegroundColor Green
Write-Host "[OK] Secure image ready: $DOCKER_IMAGE" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Disconnect from internet (air-gap your system)" -ForegroundColor Yellow
Write-Host "2. Run: .\secure_vault_workflow.ps1" -ForegroundColor Yellow
Write-Host "3. After operations, reconnect to internet" -ForegroundColor Yellow
Write-Host ""
Write-Host "[SECURITY] Remember to:" -ForegroundColor Cyan
Write-Host "- Use a dedicated, offline machine for crypto operations" -ForegroundColor Cyan
Write-Host "- Never run this on shared or cloud systems" -ForegroundColor Cyan
Write-Host "- Physically disconnect network cables" -ForegroundColor Cyan
