+++
title = "Your First Container"
description = "Create a container, manage it, and learn how to run background processes like tmux."
weight = 2
+++

This tutorial assumes sdme is already installed (see the
[downloads page](/) and that `systemd-container` is installed on
your system so `systemd-nspawn` and `machinectl` are available.

{% callout(type="warn", title="Note") %}
sdme requires root for all operations. Every `sdme` command in this tutorial must be run as root or with `sudo`.
{% end %}

## Create and enter a container

The `sdme new` command creates a container, starts it, and drops you into a
shell, all in one step:

```sh
sudo sdme new
```

By default, sdme creates an overlayfs clone of your host root filesystem.
The base rootfs stays untouched; any changes you make inside the container
are written to the overlay's upper layer.

sdme assigns a random name to the container. You can also choose your own
name by passing it as an argument, e.g. `sudo sdme new mycontainer`.

You'll see output similar to:

```
$ sudo sdme new
creating 'araciubaia'
starting 'araciubaia'
joining 'araciubaia'
host rootfs container: joining as user 'fiorix' with opaque dirs /etc/systemd/system, /var/log
Connected to machine araciubaia. Press ^] three times within 1s to exit session.
araciubaia ~ $
```

You are now inside the container. It looks and feels like your host system
but any changes are isolated to this container.

### Exiting the container

Type `exit` or press `Ctrl+]` three times quickly. This detaches from the
container shell; the container keeps running in the background.

## Basic container management

Back on the host, you can manage your container with these commands.

{% callout(type="tip", title="Tip") %}
You don't have to type the full name: sdme does prefix matching, so `sudo sdme join ara` would work if no other container name starts with `ara`.
{% end %}

```sh
# List running containers
sudo sdme ps

# Re-enter the container
sudo sdme join araciubaia

# Run a command without entering (requires full command paths)
sudo sdme exec araciubaia -- /bin/cat /etc/os-release

# Stop the container
sudo sdme stop araciubaia

# Start it again
sudo sdme start araciubaia

# Stop and delete the container
sudo sdme rm araciubaia
```

Replace `araciubaia` with whatever name sdme assigned to your container.

## Running tmux (and other background processes)

Once inside the container, you might want to start `tmux` to keep processes
running after you detach from the shell. If you try running `tmux` directly,
you'll notice that it gets killed as soon as you exit the shell.

{% callout(type="warn", title="Why does tmux die when I exit?") %}
systemd tracks every process inside a login session using cgroups. When your shell exits, systemd terminates all remaining processes in that session scope, including tmux.
{% end %}

The fix is to run tmux (or any long-lived process) inside its own systemd
scope, which gives it an independent lifecycle from your login session:

```sh
systemd-run --scope tmux
```

This tells systemd to run `tmux` in a new transient scope unit instead of
your session scope. When you exit the shell, systemd only tears down your
session; the tmux scope is separate, so it stays alive.

You can rejoin it later by entering the container and running:

```sh
tmux attach
```
