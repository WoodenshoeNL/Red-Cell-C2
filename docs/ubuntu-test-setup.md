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
display  = ":99"
```

---

## 10. Set up Xvfb for screenshot scenario (scenario 08)

Scenario 08 captures a screenshot from the agent.  On a headless Linux target,
an X virtual framebuffer must be running before the scenario runs.

### Install

```bash
sudo apt-get install -y xvfb x11-utils
```

`x11-utils` provides `xdpyinfo`, which the test harness uses as a pre-flight
check to verify the display is actually accepting connections before deploying
the agent.

### Persistent service (recommended)

Create a systemd user service so Xvfb survives reboots and SSH session ends:

```bash
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/xvfb-99.service << 'EOF'
[Unit]
Description=Xvfb virtual framebuffer :99
After=default.target

[Service]
ExecStart=/usr/bin/Xvfb :99 -screen 0 1920x1080x24
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now xvfb-99.service

# Allow the service to stay running after logout (requires sudo)
sudo loginctl enable-linger rctest
```

Verify:

```bash
DISPLAY=:99 xdpyinfo | head -3
# Should print "name of display:    :99" (or similar)
```

### Quick one-shot start (for ad-hoc runs)

```bash
Xvfb :99 -screen 0 1920x1080x24 &>/tmp/xvfb.log &
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Permission denied (publickey)` | Check `~/.ssh/authorized_keys` permissions — must be `600`, owned by `rctest` |
| `Connection refused` | Verify `sshd` is running: `sudo systemctl status ssh` |
| Payload won't execute | Ensure `rctest` is in the `sudo` group and has NOPASSWD sudoers entry |
| AppArmor blocks execution | Check `sudo dmesg | grep apparmor` and add an AppArmor exception if needed |
| Scenario 08 skipped ("no DISPLAY") | `display` key missing from `targets.toml [linux]` — set `display = ":99"` and ensure Xvfb is running |
| `xdpyinfo` fails over SSH | Xvfb not running; start with `systemctl --user start xvfb-99.service` or the one-shot command above |

---

## Disable automatic updates during test runs (optional)

Automatic security updates can interfere with long test runs:

```bash
sudo systemctl disable --now unattended-upgrades
```

> **Note**: Only do this on an isolated test VM, never on a production machine.
