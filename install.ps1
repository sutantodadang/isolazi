# isolazi Installation Script for Windows
# One-click install via PowerShell
# Downloads pre-built binaries from GitHub releases

param(
    [switch]$Uninstall,
    [switch]$Help,
    [string]$InstallDir = "$env:USERPROFILE\.isolazi",
    [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"

# Configuration
$Repo = "sutantodadang/isolazi"

# Colors
function Write-Info { Write-Host "[INFO] $args" -ForegroundColor Blue }
function Write-Success { Write-Host "[SUCCESS] $args" -ForegroundColor Green }
function Write-Warn { Write-Host "[WARNING] $args" -ForegroundColor Yellow }
function Write-Err { Write-Host "[ERROR] $args" -ForegroundColor Red; exit 1 }

function Show-Banner {
    Write-Host ""
    Write-Host "  _           _           _ " -ForegroundColor Cyan
    Write-Host " (_)___  ___ | | __ _ ___(_)" -ForegroundColor Cyan
    Write-Host " | / __|/ _ \| |/ _`` |_  / |" -ForegroundColor Cyan
    Write-Host " | \__ \ (_) | | (_| |/ /| |" -ForegroundColor Cyan
    Write-Host " |_|___/\___/|_|\__,_/___|_|" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Container Runtime Installation Script" -ForegroundColor White
    Write-Host "======================================" -ForegroundColor White
    Write-Host ""
}

function Show-Help {
    Write-Host "isolazi Installation Script"
    Write-Host ""
    Write-Host "Usage: .\install.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Help           Show this help message"
    Write-Host "  -Uninstall      Uninstall isolazi"
    Write-Host "  -InstallDir     Custom installation directory (default: ~/.isolazi)"
    Write-Host "  -Version        Version to install (default: latest)"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\install.ps1                           # Install latest version"
    Write-Host "  .\install.ps1 -Version v0.1.11          # Install specific version"
    Write-Host "  .\install.ps1 -InstallDir C:\isolazi    # Custom install location"
    Write-Host "  .\install.ps1 -Uninstall                # Remove isolazi"
    Write-Host ""
    Write-Host "Remote install:"
    Write-Host "  irm https://raw.githubusercontent.com/$Repo/main/install.ps1 | iex"
    Write-Host ""
}

function Get-Platform {
    $arch = $null
    try { $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() } catch {}

    if ([string]::IsNullOrWhiteSpace($arch)) { $arch = $env:PROCESSOR_ARCHITECTURE }
    if ([string]::IsNullOrWhiteSpace($arch)) { $arch = $env:PROCESSOR_ARCHITEW6432 }

    if ([string]::IsNullOrWhiteSpace($arch)) {
        try {
            $osArch = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).OSArchitecture
            if ($osArch -match "64") { $arch = "X64" }
            elseif ($osArch -match "32") { $arch = "X86" }
        } catch {}
    }

    if ([string]::IsNullOrWhiteSpace($arch)) {
        if ([Environment]::Is64BitOperatingSystem) { $arch = "X64" }
    }

    $arch = $arch.ToString().ToUpperInvariant()

    switch ($arch) {
        "X64" { return "windows-x86_64" }
        "AMD64" { return "windows-x86_64" }
        "X86_64" { return "windows-x86_64" }
        "ARM64" { return "windows-aarch64" }
        default { Write-Err "Unsupported architecture: $arch" }
    }
}

function Get-LatestVersion {
    if ($script:Version -eq "latest") {
        Write-Info "Fetching latest release version..."
        try {
            $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
            $script:Version = $release.tag_name
        } catch {
            Write-Warn "Could not resolve 'latest' tag via API. Will attempt direct download."
        }
    }
    Write-Info "Installing version: $Version"
}

function Install-Binary {
    $BinDir = "$InstallDir\bin"
    $Platform = Get-Platform
    
    Write-Info "Detected platform: $Platform"
    
    # Try different download URL patterns
    $urls = @()
    if ($Version -eq "latest") {
        $urls += "https://github.com/$Repo/releases/latest/download/isolazi-$Platform.zip"
        $urls += "https://github.com/$Repo/releases/latest/download/isolazi-windows-x86_64.zip"
        $urls += "https://github.com/$Repo/releases/latest/download/isolazi_$Platform.zip"
        # Fallback to tar.gz
        $urls += "https://github.com/$Repo/releases/latest/download/isolazi-$Platform.tar.gz"
        $urls += "https://github.com/$Repo/releases/latest/download/isolazi-windows-x86_64.tar.gz"
    } else {
        $urls += "https://github.com/$Repo/releases/download/$Version/isolazi-$Platform.zip"
        $urls += "https://github.com/$Repo/releases/download/$Version/isolazi-windows-x86_64.zip"
        $urls += "https://github.com/$Repo/releases/download/$Version/isolazi_$Platform.zip"
        $urls += "https://github.com/$Repo/releases/download/$Version/isolazi-$Platform.tar.gz"
        $urls += "https://github.com/$Repo/releases/download/$Version/isolazi-windows-x86_64.tar.gz"
    }
    
    $tmpDir = Join-Path $env:TEMP "isolazi-install-$(Get-Random)"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    
    $downloaded = $false
    $archivePath = ""
    
    foreach ($url in $urls) {
        Write-Info "Trying: $url"
        try {
            if ($url -match "\.zip$") {
                $archivePath = Join-Path $tmpDir "isolazi.zip"
            } else {
                $archivePath = Join-Path $tmpDir "isolazi.tar.gz"
            }
            
            Invoke-WebRequest -Uri $url -OutFile $archivePath -UseBasicParsing
            $downloaded = $true
            Write-Success "Downloaded from: $url"
            break
        } catch {
            Write-Warn "Failed: $url"
        }
    }
    
    if (-not $downloaded) {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Err "Failed to download binary. Check releases at: https://github.com/$Repo/releases"
    }
    
    Write-Info "Extracting archive..."
    
    # Create bin directory
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    
    $extractDir = Join-Path $tmpDir "extracted"
    New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
    
    # Extract based on file type
    if ($archivePath -match "\.zip$") {
        Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force
    } else {
        # For tar.gz, use tar command (available in Windows 10+)
        tar -xzf $archivePath -C $extractDir
    }
    
    # Find the binary
    $binary = Get-ChildItem -Path $extractDir -Filter "isolazi.exe" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $binary) {
        $binary = Get-ChildItem -Path $extractDir -Filter "isolazi" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    
    if (-not $binary) {
        # List contents for debugging
        Write-Info "Archive contents:"
        Get-ChildItem -Path $extractDir -Recurse -File | ForEach-Object { Write-Host $_.FullName }
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Err "Could not find isolazi binary in the downloaded archive"
    }
    
    # Copy binary (ensure .exe extension on Windows)
    $destPath = Join-Path $BinDir "isolazi.exe"
    Copy-Item -Path $binary.FullName -Destination $destPath -Force
    
    # Also copy benchmark binary if present
    $benchBinary = Get-ChildItem -Path $extractDir -Filter "isolazi-bench*" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($benchBinary) {
        $benchDest = Join-Path $BinDir "isolazi-bench.exe"
        Copy-Item -Path $benchBinary.FullName -Destination $benchDest -Force
        Write-Info "Also installed isolazi-bench"
    }
    
    # Cleanup
    Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Success "Binary installed to $destPath"
    
    return $BinDir
}

function Add-ToPath {
    param([string]$BinDir)
    
    Write-Info "Adding to PATH..."
    
    # Get current user PATH
    $currentPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    
    # Check if already in PATH
    if ($currentPath -split ";" | Where-Object { $_ -eq $BinDir }) {
        Write-Info "Directory already in PATH"
        return
    }
    
    # Add to user PATH
    $newPath = "$currentPath;$BinDir"
    [System.Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    
    # Update current session PATH
    $env:Path = "$env:Path;$BinDir"
    
    Write-Success "Added $BinDir to user PATH"
    
    # Also add to PowerShell profile for convenience
    $profileDir = Split-Path $PROFILE -Parent
    if (-not (Test-Path $profileDir)) {
        New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    }
    
    if (-not (Test-Path $PROFILE)) {
        New-Item -ItemType File -Path $PROFILE -Force | Out-Null
    }
    
    $profileContent = Get-Content $PROFILE -Raw -ErrorAction SilentlyContinue
    if (-not ($profileContent -match [regex]::Escape($BinDir))) {
        Add-Content -Path $PROFILE -Value ""
        Add-Content -Path $PROFILE -Value "# isolazi"
        Add-Content -Path $PROFILE -Value "`$env:Path += `";$BinDir`""
        Write-Info "Added to PowerShell profile: $PROFILE"
    }
}

function Test-Installation {
    param([string]$BinDir)
    
    Write-Info "Verifying installation..."
    
    $exePath = "$BinDir\isolazi.exe"
    
    if (Test-Path $exePath) {
        Write-Success "isolazi installed successfully!"
        Write-Host ""
        Write-Host "Installation complete!" -ForegroundColor Green
        Write-Host ""
        Write-Host "To start using isolazi, either:"
        Write-Host "  1. Open a new PowerShell/Command Prompt window, or"
        Write-Host "  2. Run: `$env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'User')"
        Write-Host ""
        Write-Host "Then try: isolazi --help"
        Write-Host ""
        
        # Try to show version
        try {
            & $exePath --version
        } catch {}
    } else {
        Write-Err "Installation verification failed"
    }
}

function Uninstall-Isolazi {
    Write-Warn "Uninstalling isolazi..."
    
    $BinDir = "$InstallDir\bin"
    
    # Remove installation directory
    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-Info "Removed $InstallDir"
    }
    
    # Remove from PATH
    $currentPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $newPath = ($currentPath -split ";" | Where-Object { $_ -ne $BinDir -and $_ -ne "" }) -join ";"
    [System.Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Info "Removed from PATH"
    
    # Remove from PowerShell profile
    if (Test-Path $PROFILE) {
        $content = Get-Content $PROFILE | Where-Object { 
            $_ -notmatch "isolazi" -and $_ -notmatch [regex]::Escape($BinDir)
        }
        Set-Content -Path $PROFILE -Value $content
        Write-Info "Removed from PowerShell profile"
    }
    
    Write-Success "isolazi has been uninstalled"
}

# Main
function Main {
    Show-Banner
    
    if ($Help) {
        Show-Help
        exit 0
    }
    
    if ($Uninstall) {
        Uninstall-Isolazi
        exit 0
    }
    
    Get-LatestVersion
    $BinDir = Install-Binary
    Add-ToPath -BinDir $BinDir
    Test-Installation -BinDir $BinDir
}

Main
