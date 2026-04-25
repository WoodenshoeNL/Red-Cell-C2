#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Idempotent Windows 11 test-VM setup for the Red Cell C2 automated test harness.
.DESCRIPTION
    Configures OpenSSH, firewall, test user, Defender exclusion, and Windows Update
    pause on a fresh Windows 11 VM. Safe to re-run — each step checks current state
    before making changes.
.PARAMETER PubKey
    SSH public key string (e.g. "ssh-ed25519 AAAA... comment") or path to a .pub file.
.EXAMPLE
    .\setup-win11-test-vm.ps1 "ssh-ed25519 AAAAC3Nz... red-cell-test"
    .\setup-win11-test-vm.ps1 C:\Users\admin\Desktop\red_cell_test.pub
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$PubKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Helpers -----------------------------------------------------------------

function Write-Ok   { param([string]$Msg) Write-Host "[ok]    $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "[warn]  $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "[ERROR] $Msg" -ForegroundColor Red }

# --- Resolve the public key --------------------------------------------------

if (Test-Path $PubKey) {
    $PubKey = (Get-Content -Path $PubKey -Raw).Trim()
}
if ($PubKey -notmatch '^ssh-(ed25519|rsa|ecdsa)') {
    Write-Err "Does not look like an SSH public key: $PubKey"
    exit 1
}

$TestUser = "rctest"
$WorkDir  = "C:\Temp\rc-test"
$Changed  = $false

# --- 1. Install OpenSSH Server ----------------------------------------------

$sshCap = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Server*' }
if ($sshCap.State -eq 'Installed') {
    Write-Ok "OpenSSH Server already installed"
} else {
    Write-Warn "Installing OpenSSH Server..."
    Add-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0" | Out-Null
    $Changed = $true
    Write-Ok "OpenSSH Server installed"
}

# --- 2. Enable and start sshd -----------------------------------------------

$svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Write-Err "sshd service not found after install — reboot and re-run"
    exit 1
}
if ($svc.StartType -ne 'Automatic') {
    Set-Service -Name sshd -StartupType Automatic
    $Changed = $true
}
if ($svc.Status -ne 'Running') {
    Start-Service sshd
    $Changed = $true
    Write-Ok "sshd started and set to Automatic"
} else {
    Write-Ok "sshd already running (startup: $($svc.StartType))"
}

# --- 3. Firewall rule for TCP 22 --------------------------------------------

$fwRule = Get-NetFirewallRule -Name 'sshd' -ErrorAction SilentlyContinue
if ($null -ne $fwRule) {
    Write-Ok "Firewall rule 'sshd' already exists"
} else {
    Write-Warn "Creating firewall rule for TCP 22..."
    New-NetFirewallRule -Name sshd `
        -DisplayName 'OpenSSH Server (sshd)' `
        -Enabled True -Direction Inbound `
        -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    $Changed = $true
    Write-Ok "Firewall rule created"
}

# --- 4. Create test user + add to Administrators ----------------------------

$user = Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue
if ($null -ne $user) {
    Write-Ok "User '$TestUser' already exists"
} else {
    Write-Warn "Creating local user '$TestUser'..."
    $bytes = [byte[]]::new(24)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $randomPw = [Convert]::ToBase64String($bytes) + "!Aa1"
    $securePw = ConvertTo-SecureString $randomPw -AsPlainText -Force
    New-LocalUser -Name $TestUser -Password $securePw `
        -FullName "Red Cell Test" `
        -Description "Automated test account" | Out-Null
    $Changed = $true
    Write-Ok "User '$TestUser' created (password is random — key auth only)"
}

$members = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*\$TestUser" }
if ($null -ne $members) {
    Write-Ok "'$TestUser' already in Administrators"
} else {
    Add-LocalGroupMember -Group "Administrators" -Member $TestUser
    $Changed = $true
    Write-Ok "Added '$TestUser' to Administrators"
}

# --- 5. Deploy SSH public key -----------------------------------------------

$authKeysPath = "C:\ProgramData\ssh\administrators_authorized_keys"
$sshDir = Split-Path $authKeysPath
if (-not (Test-Path $sshDir)) {
    New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
}

$needsWrite = $true
if (Test-Path $authKeysPath) {
    $existing = Get-Content -Path $authKeysPath -Raw -ErrorAction SilentlyContinue
    if ($existing -and $existing.Contains($PubKey)) {
        Write-Ok "Public key already in administrators_authorized_keys"
        $needsWrite = $false
    }
}
if ($needsWrite) {
    Write-Warn "Writing public key to administrators_authorized_keys..."
    Add-Content -Path $authKeysPath -Value $PubKey -Encoding UTF8
    $Changed = $true
    Write-Ok "Public key written"
}

# Fix ACLs — OpenSSH on Windows requires SYSTEM + Administrators only
icacls $authKeysPath /inheritance:r /grant "SYSTEM:(F)" /grant "Administrators:(F)" | Out-Null
Write-Ok "ACLs set on administrators_authorized_keys"

# --- 6. Create work directory ------------------------------------------------

if (Test-Path $WorkDir) {
    Write-Ok "Work directory $WorkDir already exists"
} else {
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    $Changed = $true
    Write-Ok "Created $WorkDir"
}

# --- 7. Defender exclusion for work directory --------------------------------

$exclusions = (Get-MpPreference).ExclusionPath
if ($exclusions -and ($exclusions -contains $WorkDir)) {
    Write-Ok "Defender exclusion for $WorkDir already set"
} else {
    Write-Warn "Adding Defender exclusion for $WorkDir..."
    Add-MpPreference -ExclusionPath $WorkDir
    $Changed = $true
    Write-Ok "Defender exclusion added"
}

# --- 8. Pause Windows Update ------------------------------------------------

# Pause automatic updates for 35 days (maximum via policy).
# Uses the UX/Settings pause mechanism which is the safest approach on
# non-domain-joined Windows 11 machines.
$wuKey = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
$pauseEnd = (Get-Date).AddDays(35).ToString("yyyy-MM-ddTHH:mm:ssZ")

$currentPause = Get-ItemProperty -Path $wuKey -Name "PausedFeatureDate" -ErrorAction SilentlyContinue
if ($null -ne $currentPause -and $currentPause.PausedFeatureDate -ge (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")) {
    Write-Ok "Windows Update already paused"
} else {
    Write-Warn "Pausing Windows Update for 35 days..."
    if (-not (Test-Path $wuKey)) {
        New-Item -Path $wuKey -Force | Out-Null
    }
    Set-ItemProperty -Path $wuKey -Name "PausedFeatureStatus"  -Value 1
    Set-ItemProperty -Path $wuKey -Name "PausedFeatureDate"    -Value $pauseEnd
    Set-ItemProperty -Path $wuKey -Name "PausedQualityStatus"  -Value 1
    Set-ItemProperty -Path $wuKey -Name "PausedQualityDate"    -Value $pauseEnd
    $Changed = $true
    Write-Ok "Windows Update paused until $pauseEnd"
}

# --- 9. Summary and verification command ------------------------------------

Write-Host ""
if ($Changed) {
    Write-Warn "Changes were made — verify SSH from your dev machine:"
} else {
    Write-Ok "Nothing changed — VM was already configured."
    Write-Host "Verify SSH from your dev machine:"
}

$hostname = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
    Select-Object -First 1).IPAddress

if ($hostname) {
    Write-Host ""
    Write-Host "  ssh -i ~/.ssh/red_cell_test $TestUser@$hostname whoami" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Expected output: $env:COMPUTERNAME\$TestUser"
} else {
    Write-Host ""
    Write-Host "  ssh -i ~/.ssh/red_cell_test $TestUser@<this-vm-ip> whoami" -ForegroundColor Cyan
    Write-Host ""
}

Write-Host ""
Write-Host "Then update targets.toml:" -ForegroundColor Cyan
Write-Host @"

[windows]
host     = "$hostname"
port     = 22
user     = "$TestUser"
key      = "~/.ssh/red_cell_test"
work_dir = "$WorkDir"
"@
