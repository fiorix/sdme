+++
title = "Running Long-Lived Services"
description = "Install and run services like nginx or MariaDB inside sdme containers."
weight = 4
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

## Install a service

Create a container and enter it:

```sh
sudo sdme new mywebserver -r fedora
```

Inside the container, install nginx:

```sh
dnf install -y nginx
systemctl enable --now nginx
```

From the host, verify it's running:

```sh
curl http://localhost
```

You should see the default nginx welcome page. This works because sdme
containers share the host network by default.

Inside the container, you manage services with standard systemd commands:
`systemctl status nginx`, `systemctl restart nginx`,
`journalctl -u nginx`, etc. Services enabled with `systemctl enable`
start automatically when the container boots.

## Persisting across restarts

Any packages you install and files you create are written to the
container's overlayfs upper layer. They persist across `sdme stop`
and `sdme start`. Only `sdme rm` deletes them.

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
