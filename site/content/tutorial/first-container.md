+++
title = "Your First Container"
description = "Create a container, manage it, and learn how to run background processes like tmux."
weight = 2
+++

sdme runs full Linux systems as containers, not just application
processes. Each container boots its own
[systemd](https://systemd.io/) init, has its own journal, and
supports `systemctl`, `journalctl`, and everything you would
expect on a real machine. If you are coming from Docker or Podman,
think of it as a lightweight VM without the hypervisor overhead.

This tutorial assumes sdme is already installed (see the
[downloads page](/)) and that `systemd-container` is installed on
your system so
[systemd-nspawn](https://www.freedesktop.org/software/systemd/man/latest/systemd-nspawn.html)
and
[machinectl](https://www.freedesktop.org/software/systemd/man/latest/machinectl.html)
are available.

{% callout(type="warn", title="Note") %}
sdme requires root for all operations. Every `sdme` command in this tutorial must be run as root or with `sudo`.
{% end %}

## Create and enter a container

The `sdme new` command creates a container, starts it, and drops you into a
shell, all in one step:

```sh
sudo sdme new
```

By default, sdme creates an overlayfs clone (a copy-on-write snapshot)
of your host root filesystem. The base rootfs stays untouched; any
changes you make inside the container are written to the overlay's
upper layer.

When no name is given, sdme generates a random one. You'll see output
similar to:

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

{% callout(type="tip", title="Tip") %}
All sdme commands support name prefix matching. If your container is called `araciubaia`, typing `sudo sdme join ara` is enough, as long as no other container name starts with `ara`.
{% end %}

## Naming your containers

Random names work for quick experiments, but named containers are easier
to script and remember. Delete the auto-named container and create a
named one:

```sh
sudo sdme rm araciubaia
sudo sdme new foobar
```

The rest of this tutorial uses `foobar` so every command is
copy-paste ready.

## Re-entering and running commands

Re-enter the container shell:

```sh
sudo sdme join foobar
```

Run a command without entering (no $PATH set, requires full path):

```sh
sudo sdme exec foobar -- /bin/cat /etc/os-release
```

Stop and delete the container when you're done:

```sh
sudo sdme rm foobar
```

For listing, stopping, starting, restarting, and other daily operations,
see [Day-to-Day Management](@/tutorial/management.md).

## Running tmux (and other background processes)

Once inside the container, you might want to start `tmux` to keep processes
running after you detach from the shell. If you try running `tmux` directly,
you'll notice that it gets killed as soon as you exit the shell.

{% callout(type="warn", title="Why does tmux die when I exit?") %}
systemd tracks every process inside a login session using [cgroups](https://docs.kernel.org/admin-guide/cgroup-v2.html) (process groups used for resource tracking and lifecycle management). When your shell exits, systemd terminates all remaining processes in that session scope, including tmux.
{% end %}

The fix is to run tmux (or any long-lived process) inside its own systemd
scope, which gives it an independent lifecycle from your login session:

```sh
systemd-run --scope tmux
```

This tells systemd to run `tmux` in a new transient scope unit (an
independent process group) instead of your session scope. When you exit the shell, systemd only tears down your
session; the tmux scope is separate, so it stays alive.

You can rejoin it later by entering the container and running:

```sh
tmux attach
```
