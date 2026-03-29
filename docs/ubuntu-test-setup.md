# Enabling SSH on Ubuntu (test machine setup)

This guide sets up OpenSSH on an Ubuntu Desktop or Server test machine so the
automated test harness can deploy payloads and run commands over SSH.

---

## 1. Install OpenSSH Server

```bash
sudo apt-get update
sudo apt-get install -y openssh-server
```

Verify it is running:

```bash
sudo systemctl status ssh
```

---

## 2. Start and enable the SSH service

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

---

## 3. Allow SSH through the firewall (if ufw is active)

```bash
sudo ufw allow ssh
sudo ufw status
```

---

## 4. Create a dedicated test user

```bash
# Create the user (no interactive password — key auth only)
sudo useradd -m -s /bin/bash rctest

# Add to sudo group (needed to execute payloads and install test dependencies)
sudo usermod -aG sudo rctest

# Allow sudo without a password (for automated test runs)
echo 'rctest ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/rctest
sudo chmod 0440 /etc/sudoers.d/rctest
```

---

## 5. Set up SSH key authentication

On your **development machine**, generate a key pair if you don't have one:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/red_cell_test -C "red-cell-test"
```

On the **Ubuntu test machine**, add the public key:

```bash
# Switch to the test user
sudo -u rctest bash

# Create the .ssh directory
mkdir -p ~/.ssh
chmod 700 ~/.ssh

# Paste your public key
echo "ssh-ed25519 AAAA... red-cell-test" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

---

## 6. Configure the SSH server (optional hardening)

Edit `/etc/ssh/sshd_config`:

```
PubkeyAuthentication yes
PasswordAuthentication no    # disable once key auth is confirmed working
PermitRootLogin no
```

Restart the service after changes:

```bash
sudo systemctl restart ssh
```

---

## 7. Create the test work directory

```bash
sudo -u rctest mkdir -p /tmp/rc-test
```

---

## 8. Verify from your dev machine

```bash
ssh -i ~/.ssh/red_cell_test -p 22 rctest@<ubuntu-ip> "whoami && uname -a"
# Expected: rctest
#           Linux <hostname> ...
```

---

## 9. Update targets.toml

```toml
[linux]
host     = "<ubuntu-ip>"
port     = 22
user     = "rctest"
key      = "~/.ssh/red_cell_test"
work_dir = "/tmp/rc-test"
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Permission denied (publickey)` | Check `~/.ssh/authorized_keys` permissions — must be `600`, owned by `rctest` |
| `Connection refused` | Verify `sshd` is running: `sudo systemctl status ssh` |
| Payload won't execute | Ensure `rctest` is in the `sudo` group and has NOPASSWD sudoers entry |
| AppArmor blocks execution | Check `sudo dmesg | grep apparmor` and add an AppArmor exception if needed |

---

## Disable automatic updates during test runs (optional)

Automatic security updates can interfere with long test runs:

```bash
sudo systemctl disable --now unattended-upgrades
```

> **Note**: Only do this on an isolated test VM, never on a production machine.
