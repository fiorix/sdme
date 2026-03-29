+++
title = "Running Long-Lived Services"
description = "Install and run services like nginx inside sdme containers."
weight = 5
+++

Since sdme containers boot a full systemd, you can install and run
services the same way you would on a regular Linux system.

## Import a rootfs

Import a rootfs to use as a container template. This example uses
Fedora, but any [supported distribution](/tutorial/different-rootfs/#supported-distributions)
works:

```sh
sudo sdme fs import fedora quay.io/fedora/fedora
```

## Create a container

We recommend using `--network-zone` and `--hardened` for service
containers:

- `--network-zone=services` gives the container its own network
  namespace with DNS, avoiding port conflicts with the host. Other
  containers can later join the same zone and reach each other by
  hostname.
- `--hardened` enables user namespace isolation so root inside the
  container is not root on the host.

```sh
sudo sdme new mywebserver -r fedora --network-zone=services --hardened
```

## Install a service

Inside the container, install nginx:

```sh
dnf install -y nginx
systemctl enable --now nginx
```

Inside the container, you manage services with standard systemd
commands: `systemctl status nginx`, `systemctl restart nginx`,
`journalctl -u nginx`, etc. Services enabled with `systemctl enable`
start automatically when the container boots.

Exit the container shell with `exit`, `Ctrl+D`, or `Ctrl+]` three
times to return to the host.

## Verify from the host

Containers in a zone are reachable by IP from the host. Find the
container's IP with `sdme ps`:

```sh
sudo sdme ps
```

The ADDRESSES column shows the container's IP. Then from the host:

```sh
curl http://<container-ip>
```

## Inter-container communication

Other containers on the same zone can reach the nginx container by
hostname:

```sh
sudo sdme new myclient -r fedora --network-zone=services --hardened
```

Inside the client:

```sh
curl http://mywebserver
```

This works because zone containers use LLMNR for hostname discovery.
The host cannot resolve container names (it is not part of the zone),
but it can reach containers by IP.

## Auto-starting the container on boot

If you want the container (and its services) to start automatically
when the host boots:

```sh
sudo sdme enable mywebserver
```

## Running interactive programs with tmux

If you need to run interactive programs inside the container (like a
terminal multiplexer), use `systemd-run --scope` so they survive
after you exit the shell:

```sh
systemd-run --scope tmux
```

Without `systemd-run --scope`, systemd terminates all processes in
your login session when you exit. See the
[your first container](/tutorial/first-container/#running-tmux-and-other-background-processes)
tutorial for more details.

## Sharing files with the host

You can bind-mount host directories into the container at creation
time using the `-b` flag. See the
[bind mounts and OCI volumes](/tutorial/bind-mounts-volumes/) tutorial
for examples.
