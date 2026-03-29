# Enabling SSH on Windows 11 (test machine setup)

This guide sets up OpenSSH on a Windows 11 test machine so the automated
test harness can deploy payloads and run commands over SSH.

---

## 1. Install OpenSSH Server

Open **PowerShell as Administrator** and run:

```powershell
# Check if already installed
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

# Install the SSH server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

---

## 2. Start and enable the SSH service

```powershell
# Start the service
Start-Service sshd

# Set it to start automatically on boot
Set-Service -Name sshd -StartupType Automatic
```

---

## 3. Allow SSH through Windows Firewall

This is usually created automatically, but verify it exists:

```powershell
Get-NetFirewallRule -Name *ssh*
```

If no rule exists, create one:

```powershell
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' `
  -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

---

## 4. Create a dedicated test user

```powershell
# Create the user
$password = ConvertTo-SecureString "YourStrongPassword" -AsPlainText -Force
New-LocalUser -Name "rctest" -Password $password -FullName "Red Cell Test" `
  -Description "Automated test account"

# Add to Administrators group (needed to execute payloads)
Add-LocalGroupMember -Group "Administrators" -Member "rctest"
```

---

## 5. Set up SSH key authentication (recommended)

On your **development machine**, generate a key pair if you don't have one:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/red_cell_test -C "red-cell-test"
```

On the **Windows 11 test machine**, add the public key.
For Administrator accounts, OpenSSH uses a special path:

```powershell
# Create the administrators_authorized_keys file
$key = "ssh-ed25519 AAAA... red-cell-test"  # paste your public key here
$path = "C:\ProgramData\ssh\administrators_authorized_keys"
New-Item -ItemType File -Path $path -Force
Set-Content -Path $path -Value $key

# Fix permissions (OpenSSH is strict about this)
icacls $path /inheritance:r /grant "SYSTEM:(F)" /grant "Administrators:(F)"
```

---

## 6. Configure the SSH server (optional hardening)

Edit `C:\ProgramData\ssh\sshd_config`:

```
PubkeyAuthentication yes
PasswordAuthentication no    # disable once key auth is confirmed working
PermitRootLogin no
```

Restart the service after changes:

```powershell
Restart-Service sshd
```

---

## 7. Verify from your dev machine

```bash
ssh -i ~/.ssh/red_cell_test -p 22 rctest@<windows-ip> "whoami"
# Expected output: <hostname>\rctest
```

---

## 8. Update targets.toml

```toml
[windows]
host     = "<windows-ip>"
port     = 22
user     = "rctest"
key      = "~/.ssh/red_cell_test"
work_dir = "C:\\Temp\\rc-test"
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Permission denied (publickey)` | Check `administrators_authorized_keys` permissions — must be owned by SYSTEM/Administrators only |
| `Connection refused` | Verify `sshd` service is running: `Get-Service sshd` |
| `ssh_exchange_identification` | Firewall rule missing — re-run step 3 |
| Payload won't execute | Ensure the test user is in the Administrators group and Windows Defender exclusion is set for `work_dir` |

---

## Windows Defender exclusion for test directory

To prevent Defender from quarantining test payloads:

```powershell
Add-MpPreference -ExclusionPath "C:\Temp\rc-test"
```

> **Note**: Only do this on an isolated test VM, never on a production machine.
