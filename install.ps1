# Windows PowerShell installation script for ccp
[CmdletBinding()]
param(
    [string]$Version = $env:CCP_VERSION,
    [string]$Repo = $(if ($env:CCP_REPO) { $env:CCP_REPO } else { "smresponsibilities/ccp" }),
    [string]$InstallDir = $(if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { "$env:USERPROFILE\.ccp\bin" })
)

$ErrorActionPreference = 'Stop'

$BinaryName = "ccp.exe"
$AssetName = "ccp-windows-amd64.zip"

# CCP_DOWNLOAD_BASE lets you install from a mirror (or a local server when testing).
if ($env:CCP_DOWNLOAD_BASE) {
    $DownloadUrl = $env:CCP_DOWNLOAD_BASE.TrimEnd('/') + "/$AssetName"
} elseif ($Version) {
    $DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$AssetName"
} else {
    $DownloadUrl = "https://github.com/$Repo/releases/latest/download/$AssetName"
}

Write-Host "==> Installing ccp (windows/amd64)..." -ForegroundColor Cyan
Write-Host "==> Downloading from: $DownloadUrl" -ForegroundColor Cyan

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ccp-install-" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
$ArchiveFile = Join-Path $TempDir $AssetName

try {
    # Ensure TLS 1.2 and TLS 1.3 are enabled
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ArchiveFile -UseBasicParsing
    
    if (-not (Test-Path $ArchiveFile)) {
        Write-Error "[ERROR] Download failed: archive file was not found."
        exit 1
    }

    # Verify the download against the SHA-256 published next to it. This catches corrupted
    # or tampered downloads; it cannot protect against a compromised GitHub account, since
    # the checksum comes from the same release.
    if ($env:CCP_SKIP_VERIFY -eq '1') {
        Write-Host "[WARN] Skipping checksum verification (CCP_SKIP_VERIFY=1)." -ForegroundColor Yellow
    } else {
        $ChecksumFile = "$ArchiveFile.sha256"
        try {
            Invoke-WebRequest -Uri "$DownloadUrl.sha256" -OutFile $ChecksumFile -UseBasicParsing
        } catch {
            throw "[ERROR] Could not download the checksum file ($DownloadUrl.sha256). Refusing to install an unverified binary. Set CCP_SKIP_VERIFY=1 to override."
        }
        $Expected = ((Get-Content -Path $ChecksumFile -Raw).Trim() -split '\s+')[0].ToLower()
        $Actual = (Get-FileHash -Path $ArchiveFile -Algorithm SHA256).Hash.ToLower()
        if ($Expected -ne $Actual) {
            throw "[ERROR] Checksum mismatch for $AssetName. Not installing. Expected $Expected but got $Actual."
        }
        Write-Host "[OK] Checksum verified." -ForegroundColor Green
    }

    Expand-Archive -Path $ArchiveFile -DestinationPath $TempDir -Force

    # Locate ccp.exe inside extracted files
    $ExtractedExe = Get-ChildItem -Path $TempDir -Filter $BinaryName -Recurse -File | Select-Object -First 1

    if (-not $ExtractedExe) {
        Write-Error "[ERROR] Could not find $BinaryName in downloaded archive."
        exit 1
    }

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $TargetExe = Join-Path $InstallDir $BinaryName
    Copy-Item -Path $ExtractedExe.FullName -Destination $TargetExe -Force

    Write-Host "[OK] ccp installed to $TargetExe" -ForegroundColor Green

    # Always ensure InstallDir is in current session PATH so ccp is immediately available
    if (($env:PATH -split ';') -notcontains $InstallDir) {
        $env:PATH = "$InstallDir;$env:PATH"
    }

    # Check and update persistent User PATH
    $UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
    $PathParts = ($UserPath -split ';') | Where-Object { $_ -ne '' }
    $NormalizedInstallDir = $InstallDir.TrimEnd('\')
    $AlreadyInPath = $PathParts | Where-Object { $_.TrimEnd('\') -ieq $NormalizedInstallDir }

    if (-not $AlreadyInPath) {
        Write-Host ""
        Write-Host "Adding $InstallDir to your persistent User PATH..." -ForegroundColor Cyan

        $NewPath = if ([string]::IsNullOrWhiteSpace($UserPath)) { $InstallDir } else { "$UserPath;$InstallDir" }
        [Environment]::SetEnvironmentVariable("Path", $NewPath, [EnvironmentVariableTarget]::User)

        Write-Host "[OK] Added $InstallDir to User PATH." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. ccp set                      (save your campus username and password)" -ForegroundColor Cyan
    Write-Host "  2. ccp                          (log in once on campus Wi-Fi and approve your portal)" -ForegroundColor Cyan
    Write-Host "  3. ccp autostart enable --now   (keep it logged in automatically)" -ForegroundColor Cyan
}
finally {
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
