# sdme

Lightweight systemd-nspawn containers with overlayfs.

## Quick install

Download a static binary from [fiorix.github.io/sdme](https://fiorix.github.io/sdme/).

Runs on Linux with systemd. Uses kernel overlayfs for copy-on-write storage. By default, containers are overlayfs clones of `/` but you can also import rootfs from other distros (Ubuntu, Debian, Fedora, NixOS; see [docs/nix](docs/nix/)).

**Why does this even exist?**
Here's my pitch: from a linux system with just systemd and sdme, you can create and run any container and cloud image that exists today. 1 binary.

Check out the [sdme architecture](docs/architecture.md) for details about what this is and how it works. The containers we create are booted systemd containers.

**On macOS?** See [docs/macos.md](docs/macos.md) for instructions using lima-vm.

## Usage

Cloning your own "/" filesystem:

```bash
sudo sdme new
```

By default, host-rootfs containers (no `-r`) make `/etc/systemd/system` and `/var/log` opaque so the host's systemd overrides and log history don't leak in. Override with `-o` or change the default via `sdme config set host_rootfs_opaque_dirs`.

Importing a root filesystem on Ubuntu with debootstrap:

```
$ debootstrap --include=dbus,systemd noble /tmp/ubuntu
$ sudo sdme fs import ubuntu /tmp/ubuntu
$ sudo sdme new -r ubuntu
```

## Importing filesystem from an OCI container

Fedora:

```
sudo sdme fs import fedora quay.io/fedora/fedora
sudo sdme new -r fedora
```

Debian:
```
sudo sdme fs import debian docker.io/debian
sudo sdme new -r debian
```

sdme can also run OCI application images (nginx, mysql, etc.) as systemd services inside a base container, with optional cross-container access via connectors. See [docs/oci.md](docs/oci.md) for details.

## Dependencies

### Runtime

| Program | Package | Required for |
|---------|---------|--------------|
| `systemd` (>= 252) | `systemd` | All commands (D-Bus communication) |
| `systemd-nspawn` | `systemd-container` | Running containers (`sdme start`) |
| `machinectl` | `systemd-container` | `sdme join`, `sdme exec`, `sdme new` |
| `journalctl` | `systemd` | `sdme logs` |
| `qemu-nbd` | `qemu-utils` | `sdme fs import` (QCOW2 images only) |

### Install all dependencies (Debian/Ubuntu)

```bash
sudo apt install systemd-container
```

For QCOW2 image imports, also install `qemu-utils`.

## Build

```bash
cargo build --release       # build the binary
cargo test                  # run all tests
cargo test <test_name>      # run a single test
make                        # same as cargo build --release
sudo make install           # install to /usr/local (does NOT rebuild)
```

