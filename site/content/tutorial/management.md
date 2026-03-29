+++
title = "Day-to-Day Management"
description = "Essential commands for managing containers: listing, logs, copying files, and troubleshooting."
weight = 4
+++

This tutorial covers the commands you'll use daily when working with
sdme containers.

## Getting help

Every sdme command has detailed `--help` output with examples,
environment variables, file locations, and exit codes. This is the
primary documentation for sdme; there is no separate manpage.

```sh
sudo sdme --help
```

Subcommands have their own help:

```sh
sudo sdme cp --help
sudo sdme fs import --help
sudo sdme new --help
```

The help text is designed to be useful both for humans on a terminal
and for AI assistants that need to understand available options.

## Listing containers

```sh
sudo sdme ps
```

This shows all containers with their status (running/stopped), health,
OS, and any active configuration (pods, userns, binds, kube).

For machine-parseable output:

```sh
sudo sdme ps --json
sudo sdme ps --json-pretty
```

JSON output always includes all fields regardless of whether any
container uses them, including the `rootfs` name that links each
container to its base root filesystem.

## Listing root filesystems

```sh
sudo sdme fs ls
```

Shows all imported root filesystems. When any rootfs has containers,
a CONTAINERS column shows the count. JSON output includes the full
list of container names:

```sh
sudo sdme fs ls --json
```

## Viewing logs

Container logs are stored in the container's journal. The `logs`
command runs `journalctl` inside the container:

```sh
sudo sdme logs mycontainer
```

Extra arguments are passed through to journalctl:

```sh
# Follow logs in real time
sudo sdme logs mycontainer -- -f

# Last 50 lines
sudo sdme logs mycontainer -- -n 50

# Logs since a specific time
sudo sdme logs mycontainer -- --since '5 min ago'
```

For OCI application containers, use `--oci` to see the app service
logs instead of the full container journal:

```sh
sudo sdme logs mycontainer --oci
```

## Copying files

`sdme cp` copies files between the host, containers, and root
filesystems. Copies are always recursive (no `-r` flag needed).
Ownership, permissions, timestamps, and extended attributes are
preserved.

### Path formats

```sh
# Host to container
sudo sdme cp ./config.txt mycontainer:/etc/config.txt

# Container to host
sudo sdme cp mycontainer:/etc/os-release .

# Host to root filesystem
sudo sdme cp ./config.txt fs:ubuntu:/etc/config.txt

# Root filesystem to host
sudo sdme cp fs:ubuntu:/etc/hostname .
```

Container and rootfs paths must be absolute (after the colon).

### Running vs stopped containers

**Running containers:** files are read and written through the
container's live mount namespace. This gives access to all paths
including `/tmp`, `/run`, and `/dev/shm`. A consistency warning is
printed because the filesystem may be changing concurrently.

**Stopped containers:** writes go to the overlayfs upper layer.
Writes to `/tmp`, `/run`, and `/dev/shm` are refused because systemd
mounts tmpfs over these directories at boot, hiding anything written
to the upper layer. Use `/var/tmp/` as an alternative.

### Copying into root filesystems

Writes to a root filesystem go directly to the rootfs directory.
Running containers that use this rootfs will **not** see the changes
because the kernel caches the overlayfs lower layer. Stop and
restart affected containers to pick up changes.

### Safety

When copying to the host, device nodes are refused by default.
Use `--force` to skip all safety checks (device nodes and
setuid/setgid warnings).

## Troubleshooting boot failures

When a container fails to start, sdme stops it but leaves the state
on disk for debugging. You can check the journal for what went wrong.

### Example: hardened host rootfs

A common issue is trying to use `--hardened` or `--strict` with a
host rootfs clone:

```sh
sudo sdme new --hardened
```

This may fail to boot because the hardened flags enable user namespace
isolation (`--userns`), which uses overlayfs idmapped mounts. If the
host rootfs contains files with `security.capability` xattrs, the
kernel refuses to create the idmapped mount.

To debug, check the container's systemd unit status:

```sh
sudo systemctl status sdme@mycontainer.service
```

Or check the system journal for nspawn errors:

```sh
sudo journalctl -u sdme@mycontainer.service -n 50
```

{% callout(type="tip", title="Tip") %}
Use `--hardened` and `--strict` with imported rootfs (e.g. `-r ubuntu`) rather than host rootfs clones. Imported rootfs are clean and don't carry host-specific xattrs that can interfere with user namespace isolation.
{% end %}
