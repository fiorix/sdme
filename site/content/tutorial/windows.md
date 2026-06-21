+++
title = "Using sdme on Windows"
description = "Set up a Linux distro with WSL2 to run sdme on Windows."
weight = 2
+++

sdme requires Linux with systemd. On Windows, use
[WSL2](https://learn.microsoft.com/windows/wsl/) to run a Linux distro.

## Prerequisites

- Windows 10 22H2 or Windows 11
- WSL2 (installed below)

## WSL setup

Install WSL2 and the default Ubuntu distro from PowerShell or Command Prompt:

```powershell
wsl --install
```

This may require a reboot. After it finishes, launch the distro (run `wsl` or
open Ubuntu from the Start menu) and create your default user on first run.

Other distros are available via `wsl --list --online` and
`wsl --install -d <distro>`.

## Enable systemd

sdme needs systemd running as PID 1. Recent Ubuntu WSL images enable it by
default. If yours does not, edit `/etc/wsl.conf` inside the distro:

```ini
[boot]
systemd=true
```

Then restart WSL from the Windows host:

```powershell
wsl --shutdown
```

Relaunch the distro and verify:

```bash
systemctl is-system-running
```

`running` or `degraded` is fine. `offline` means systemd is not PID 1, recheck
`/etc/wsl.conf`.

## Installing sdme

Inside the distro:

```bash
curl -fsSL https://sdme.io/install.sh | sudo sh
```

Verify the installation:

```bash
sdme --version
```

Alternatively, run the install from the Windows host without entering the distro:

```powershell
wsl -d Ubuntu -- bash -c 'curl -fsSL https://sdme.io/install.sh | sudo sh'
```

All sdme commands run inside the distro from this point.

## Shell alias

For common operations like creating, joining, or stopping containers, you can
add a wrapper to your host shell so you don't have to enter the distro each time.

PowerShell, add to your profile (`notepad $PROFILE`):

```powershell
function sdme { wsl sudo sdme @args }
```

Git Bash, add to `~/.bashrc`:

```bash
alias sdme='wsl sudo sdme'
```

This lets you run commands like `sdme new`, `sdme join`, `sdme ps`, and
`sdme stop` directly from the Windows terminal.

For operations that interact with the filesystem more heavily (`fs import`,
`fs export`, `fs build`, `cp`, etc.), enter the distro directly by running `wsl`
and work from inside it.

## Known limitations

- **systemd required:** sdme cannot manage units unless systemd is PID 1. See
  the systemd setup above.
- **Filesystem:** keep container rootfs and working files under the Linux
  filesystem (for example your home directory), not `/mnt/c`. Windows-mounted
  paths are slower and do not preserve Linux ownership and permissions.
- **Networking:** WSL2 defaults to a NAT network and auto-forwards `localhost`
  for services listening *inside the distro*. nspawn containers sit behind a
  second NAT inside the distro, so a container port may not be reachable from
  Windows without extra forwarding. Mirrored networking shares the host network
  and may simplify this, set it in `%UserProfile%\.wslconfig`:
  ```ini
  [wsl2]
  networkingMode=mirrored
  ```
  followed by `wsl --shutdown`. Exact reachability depends on your Windows and
  WSL version, test both modes for your setup.
