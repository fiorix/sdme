# macOS Support

sdme requires Linux with systemd. On macOS, use
[lima-vm](https://lima-vm.io/) to run a Linux VM.

## Prerequisites

- [Homebrew](https://brew.sh/)
- lima-vm: `brew install lima`

## VM setup

Create and start a VM with any systemd-based distro:

```bash
limactl create --name=dev template:ubuntu
limactl start dev
limactl shell dev
```

Other distro templates are available via `limactl create` (interactive).

## Installing sdme

Inside the VM:

```bash
curl -fsSL https://fiorix.github.io/sdme/install.sh | sudo sh
```

All sdme commands run inside the VM from this point.

## Shell alias

To run sdme directly from the Mac terminal without manually entering
the VM each time, add this alias to your shell profile:

```bash
alias sdme='limactl shell dev sudo sdme'
```

This works because lima-vm automatically maps `/Users/$USER` from
macOS into the VM at the same path, so file paths you specify on the
Mac resolve correctly inside the VM. This means commands like
`fs import`, `fs export`, and `fs build` work transparently with
files on your Mac filesystem.

Example -- import Ubuntu and start a shell, all from the Mac terminal:

```bash
sdme fs import docker.io/ubuntu:24.04 -r ubuntu
sdme new -r ubuntu
```

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
