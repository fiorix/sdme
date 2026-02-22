# NixOS rootfs for sdme

Build a minimal NixOS rootfs with systemd and D-Bus for use in sdme containers.

## Prerequisites

Install [Nix](https://nixos.org/download) (daemon mode recommended):

```bash
sh <(curl -L https://nixos.org/nix/install) --daemon --yes
```

## Build and import

```bash
sudo ./build-rootfs.sh
sudo sdme fs import --name nixos -f docs/nix/nixos-rootfs
```

The build script runs `nix-build` on `container.nix` to produce the NixOS
system closure, then copies the full `/nix/store` closure into a rootfs
directory that systemd-nspawn can boot.

The `sdme fs import` will warn about systemd not being found at standard
paths — this is expected since NixOS keeps everything under `/nix/store`.
Use `-f` to force the import.

## Use

```bash
sudo sdme create --name mybox --fs nixos
sudo sdme start mybox
sudo sdme join mybox
```

Inside the container, binaries live under `/run/current-system/sw/bin/`. The
login shell is configured automatically, so `sdme join` drops you into a
working bash session.

For `sdme exec`, use full paths:

```bash
sudo sdme exec mybox -- /run/current-system/sw/bin/systemctl status
```

## Customization

Edit `container.nix` to add packages or enable services. For example, to add
`curl` and `git`:

```nix
environment.systemPackages = with pkgs; [
  # ... existing packages ...
  curl
  git
];
```

Then rebuild and re-import:

```bash
sudo ./build-rootfs.sh
sudo sdme fs rm nixos
sudo sdme fs import --name nixos -f docs/nix/nixos-rootfs
```

## What's inside

The NixOS configuration (`container.nix`) produces a container with:

- systemd as PID 1 (via `boot.isContainer = true`)
- D-Bus system message bus
- systemd-networkd for networking
- systemd-journald for logging
- Basic userspace: bash, coreutils, util-linux, iproute2, procps, less,
  findutils, grep, sed, nano
- Root autologin on console
- Empty root password
