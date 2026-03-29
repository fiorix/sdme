+++
title = "Using sdme on macOS"
description = "Set up a Linux VM with lima-vm to run sdme on your Mac."
weight = 1
+++

sdme requires Linux with systemd. On macOS, use
[lima-vm](https://lima-vm.io/) to run a Linux VM.

## Prerequisites

- [Homebrew](https://brew.sh/)
- [lima-vm](https://lima-vm.io/)

```bash
brew install lima
```

## VM setup

Create and start a VM with any systemd-based distro:

```bash
limactl create --name=ubuntu template:ubuntu
limactl start ubuntu
limactl shell ubuntu
```

Other distro templates are available via `limactl create --list-templates`.

## Installing sdme

Inside the VM:

```bash
curl -fsSL https://fiorix.github.io/sdme/install.sh | sudo sh
```

Verify the installation:

```bash
sdme --version
```

All sdme commands run inside the VM from this point.

## Shell alias

For common operations like creating, joining, or stopping containers,
you can add an alias to your shell profile so you don't have to enter
the VM each time:

```bash
alias sdme='limactl shell ubuntu sudo sdme'
```

This lets you run commands like `sdme new`, `sdme join`, `sdme ps`,
and `sdme stop` directly from the Mac terminal.

For operations that interact with the filesystem more heavily
(`fs import`, `fs export`, `fs build`, `cp`, etc.), enter the VM
directly by running `limactl shell ubuntu` and work from inside it.

## Known limitations

- **Apple Silicon (M1/M2/M3/M4):** The VM runs Linux on aarch64.
  Container images and binaries must support `arm64`/`aarch64`.
- **File sharing:** Lima mounts macOS directories into the VM by
  default. Bind mounts (`-b`) pointing to lima-shared paths work, but
  file operations may be slower than native.
- **Networking:** Lima forwards ports from the VM to macOS. Services
  running in host-network containers are accessible on `localhost` from
  the Mac. Private-network containers require additional port forwarding
  configuration in the lima VM config.
