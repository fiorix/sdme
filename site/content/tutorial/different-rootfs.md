+++
title = "Using a Different Root Filesystem"
description = "Import other Linux distributions and create containers from them."
weight = 3
+++

By default, `sdme new` creates an overlayfs clone of your host root
filesystem. You can also import and use other distributions.

## Import a rootfs

For example, to import Ubuntu:

```sh
sudo sdme fs import ubuntu docker.io/ubuntu
```

sdme pulls the OCI image, extracts it, and installs the minimum packages
needed for `systemd-nspawn` to boot it (systemd, dbus, etc). See
[import prehooks](#import-prehooks) below for details on how this works.

## Create a container from it

```sh
sudo sdme new -r ubuntu
```

Or give it a name:

```sh
sudo sdme new mybox -r ubuntu
```

This creates a container using the imported Ubuntu rootfs instead of
cloning the host. The imported rootfs is reusable: you can create
multiple containers from the same base.

## List imported rootfs

```sh
sudo sdme fs ls
```

## Remove a rootfs

```sh
sudo sdme fs rm ubuntu
```

You cannot remove a rootfs while containers using it still exist.
The rootfs is the overlayfs lower layer for those containers, so
remove the containers first with `sdme rm`, then the rootfs.

## Supported distributions

Any OCI image with a systemd-based distro can be imported. Here are the
officially tested ones:

### Debian

```sh
sudo sdme fs import debian docker.io/debian:stable
```

### Ubuntu

```sh
sudo sdme fs import ubuntu docker.io/ubuntu
```

### Fedora

```sh
sudo sdme fs import fedora quay.io/fedora/fedora
```

### CentOS Stream

```sh
sudo sdme fs import centos quay.io/centos/centos:stream10
```

### AlmaLinux

```sh
sudo sdme fs import almalinux quay.io/almalinuxorg/almalinux:9
```

### Arch Linux / CachyOS

```sh
sudo sdme fs import archlinux docker.io/lopsided/archlinux
```

CachyOS is Arch-based and uses the same base image. If you're running
CachyOS as your host, cloning with `sudo sdme new` (no `-r`) gives
you a CachyOS container directly.

### openSUSE Tumbleweed

```sh
sudo sdme fs import opensuse registry.opensuse.org/opensuse/tumbleweed
```

### NixOS

NixOS requires a separate build process. See the
[build script](https://github.com/fiorix/sdme/blob/main/test/scripts/build-nixos-rootfs.sh)
and [nix expression](https://github.com/fiorix/sdme/blob/main/test/nix/sdme-nixos.nix)
in the repository for an example.

### Cloud images

`sdme fs import` also supports tarballs, directories, and QCOW2 disk
images. Cloud images from Ubuntu, Fedora, and others can be imported
directly from a URL. On x86_64:

```sh
sudo sdme fs import ubuntu-cloud https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64-root.tar.xz
```

On aarch64:

```sh
sudo sdme fs import ubuntu-cloud https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64-root.tar.xz
```

Cloud images typically ship with their own SSH server, may expect
cloud-init for initial configuration, and often have a default or
locked root password. They are well suited to run with
`--private-network` so their services don't conflict with the host:

```sh
sudo sdme new mycloud -r ubuntu-cloud --private-network
```

### Other sources

You can also build a rootfs with debootstrap and import the resulting
directory. On x86_64:

```sh
sudo debootstrap --include=systemd,dbus,systemd-resolved,login noble /tmp/noble http://archive.ubuntu.com/ubuntu
```

On aarch64 (including Apple Silicon via lima-vm):

```sh
sudo debootstrap --include=systemd,dbus,systemd-resolved,login noble /tmp/noble http://ports.ubuntu.com/ubuntu-ports
```

Then import it:

```sh
sudo sdme fs import ubuntu-debootstrap /tmp/noble
```

See `sdme fs import --help` for the full list of supported sources.

## Import prehooks

When sdme imports a base OS image, it detects the distribution family
and runs a set of commands inside the rootfs (via chroot) to install
the packages needed for `systemd-nspawn` to boot it: systemd, dbus,
login utilities, etc.

To see the current prehook commands for all distro families:

```sh
sudo sdme config get
```

This shows the full configuration, including the built-in defaults
for each distro family (debian, fedora, arch, suse).

### Customizing prehooks

You can override the import prehook for any distro family. The value
is a JSON array of commands:

```sh
sudo sdme config set distros.debian.import_prehook '["apt-get update","apt-get install -y systemd dbus"]'
```

To restore the built-in default, clear the override:

```sh
sudo sdme config set distros.debian.import_prehook ''
```

The `--install-packages` flag on `sdme fs import` controls whether
prehooks run at all. By default sdme runs them only when it detects
that systemd is missing from the rootfs.
