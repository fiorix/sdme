# sdme

Lightweight systemd-nspawn containers with overlayfs.

Runs on Linux with systemd. Uses kernel overlayfs for copy-on-write storage. By default, containers are overlayfs clones of `/` but you can also import rootfs from other distros (Ubuntu, Debian, Fedora, NixOS — see [docs/nix](docs/nix/)).

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

By default, host-rootfs containers (no `-r`) make `/etc/systemd/system` and `/var/log` opaque so the host's systemd overrides and log history don't leak in. Override with `-o` or change the default via `sdme config set host_rootfs_opaque_dirs`.

Importing an existing root filesystem:

```
$ debootstrap --include=dbus,systemd noble /tmp/ubuntu
$ sudo sdme fs import ubuntu /tmp/ubuntu
$ sudo sdme new -r ubuntu
```

### Container management

```bash
sudo sdme new mybox --fs ubuntu                         # create + start + join
sudo sdme create mybox --fs ubuntu                      # create a container
sudo sdme create -o /var/log -o /tmp mybox              # create with custom opaque dirs
sudo sdme start mybox                                   # start it
sudo sdme join mybox                                    # enter it (login shell)
sudo sdme join mybox /bin/bash -l                       # enter with a specific command
sudo sdme exec mybox cat /etc/os-release                # run a one-off command
sudo sdme logs mybox                                    # view logs
sudo sdme logs mybox -f                                 # follow logs
sudo sdme ps                                            # list containers
sudo sdme stop mybox                                    # stop one or more containers
sudo sdme stop --all                                    # stop all running containers
sudo sdme set mybox --memory 2G --cpus 4                # set resource limits
sudo sdme rm mybox                                      # remove it (stops if running)
sudo sdme rm --all --force                              # remove all containers (no prompt)
```

### Root filesystem management (`sdme fs`)

```bash
sudo sdme fs import ubuntu /path/to/rootfs              # import a rootfs (dir, tarball, URL, OCI, QCOW2)
sudo sdme fs build custom build.conf                    # build rootfs from config
sudo sdme fs ls                                         # list imported rootfs
sudo sdme fs rm ubuntu                                  # remove a rootfs
```
