+++
title = "Using sdme on Windows"
description = "Run sdme inside WSL 2 on Windows."
weight = 2
+++

sdme requires Linux with systemd. On Windows, use [WSL 2](https://learn.microsoft.com/en-us/windows/wsl/), which runs a real Linux kernel; current Ubuntu WSL images boot systemd by default.

## Prerequisites

- Windows 10 (version 2004 or later) or Windows 11
- WSL 2 with a systemd-based distro (Ubuntu is the default)

From an elevated PowerShell:

```powershell
wsl --install
```

This installs WSL and Ubuntu. Reboot if prompted.

## WSL setup

Start the distro:

```powershell
wsl
```

Verify systemd is running:

```bash
systemctl is-system-running
```

If it reports that systemd is not running, add the following to `/etc/wsl.conf` inside WSL:

```ini
[boot]
systemd=true
```

Then restart WSL from PowerShell with `wsl --shutdown` and start it again.

## Installing sdme

Inside WSL:

```bash
curl -fsSL https://sdme.io/install.sh | sudo sh
```

Verify the installation:

```bash
sdme --version
```

All sdme commands run inside WSL from this point.

## PowerShell alias

PowerShell aliases cannot embed arguments, so add a function to your PowerShell profile instead (open it with `notepad $PROFILE`):

```powershell
function sdme { wsl sudo sdme @args }
```

This lets you run commands like `sdme new`, `sdme join`, `sdme ps`, and `sdme stop` directly from the Windows prompt. Filesystem operations such as `fs import`, `fs build`, `cp`, and `fs export` also work through the wrapper, since WSL maps the Windows working directory to a writable `/mnt/<drive>` path.

## Known limitations

- **File sharing:** Windows drives are mounted inside WSL at `/mnt/c` and friends via drvfs. Bind mounts (`-b`) pointing there work, but file operations are slower than in the WSL filesystem; keep heavy import, export, and build data inside the WSL home for best performance.
- **Networking:** WSL 2 uses NAT by default. Services running in host-network containers are accessible on `localhost` from Windows through WSL's localhost forwarding. Private-network containers require additional port forwarding, or mirrored networking mode on Windows 11.
- **ARM devices:** On ARM-based Windows machines, WSL runs Linux on aarch64. Container images and binaries must support `arm64`/`aarch64`.
