# sdme

Lightweight systemd-nspawn containers with overlayfs.

Runs on Linux with systemd. Requires root for all operations. Uses kernel overlayfs for copy-on-write storage and `machinectl` for container management.

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

```bash
sudo sdme fs import --name ubuntu /path/to/rootfs       # import a rootfs
sudo sdme fs ls                                         # list imported rootfs
sudo sdme new --name mybox --fs ubuntu                  # create + start + join
sudo sdme create --name mybox --fs ubuntu               # create a container
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
