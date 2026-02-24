# sdme

Lightweight systemd-nspawn containers with overlayfs.

Runs on Linux with systemd. Uses kernel overlayfs for copy-on-write storage. By default, containers are overlayfs clones of `/`. You can also import rootfs from other distros (Ubuntu, Debian, Fedora, NixOS — see [docs/nix](docs/nix/)).

Quick start:

```
me@host $ sudo sdme new
creating 'maraemanavi'
starting 'maraemanavi'
joining 'maraemanavi'
Connected to machine maraemanavi. Press ^] three times within 1s to exit session.
me@maraemanavi ~ $ ps -p 1
    PID TTY          TIME CMD
      1 ?        00:00:01 systemd
```

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

## Usage

Cloning your own "/" filesystem:

```bash
sudo sdme new
```

This also checks for `$SUDO_USER` and joins the container as that user.
You can disable this with the `join_as_sudo_user` config setting — see `sdme config get`.

Creating a rootfs (imported rootfs needs systemd and dbus):

```bash
debootstrap --include=dbus,systemd noble /tmp/noble
sudo sdme fs import ubuntu /tmp/noble
sudo sdme new -r ubuntu
```

Importing Fedora 43 container image (OCI):

```bash
sudo sdme fs import fedora43 https://download.fedoraproject.org/pub/fedora/linux/releases/43/Container/x86_64/images/Fedora-Container-Base-Generic-Minimal-43-1.6.x86_64.oci.tar.xz
sudo sdme new -r fedora43
```

Importing Debian Sid:

```bash
sudo sdme fs import debian-sid https://cdimage.debian.org/images/cloud/sid/daily/latest/debian-sid-generic-amd64-daily.qcow2
sudo sdme new -r debian-sid
```

Importing a rootfs through an HTTP proxy:

```bash
sudo -E sdme fs import ubuntu https://example.com/ubuntu.tar.xz
# or
sudo https_proxy=http://proxy:3128 sdme fs import ubuntu https://example.com/ubuntu.tar.xz
```

The standard proxy environment variables are supported: `https_proxy`, `HTTPS_PROXY`, `http_proxy`, `HTTP_PROXY`, `all_proxy`, `ALL_PROXY`, `no_proxy`, `NO_PROXY`.

Pressing Ctrl+C during boot will cleanly cancel and remove the container (`sdme new`) or stop it (`sdme start`).

Note: sdme requires a permissive umask (e.g. `umask 022`, the default). If your umask strips read/execute from "other" (e.g. `umask 077`), container creation will be refused because non-root services inside the container would be unable to access the filesystem.

All other commands:

```bash
sudo sdme fs import ubuntu /path/to/rootfs               # import a rootfs (dir, tarball, URL, OCI, QCOW2)
sudo sdme fs ls                                         # list imported rootfs
sudo sdme new mybox --fs ubuntu                         # create + start + join
sudo sdme create mybox --fs ubuntu                      # create a container
sudo sdme start mybox                                   # start it
sudo sdme join mybox                                    # enter it (login shell)
sudo sdme join mybox /bin/bash -l                       # enter with a specific command
sudo sdme exec mybox cat /etc/os-release                # run a one-off command
sudo sdme logs mybox                                    # view logs
sudo sdme logs mybox -f                                 # follow logs
sudo sdme ps                                            # list containers
sudo sdme stop mybox                                    # stop one or more containers
sudo sdme rm mybox                                      # remove it (stops if running)
```
