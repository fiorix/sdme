+++
title = "Building Root Filesystems"
description = "Build custom root filesystems with sdme fs build using Dockerfile-like configs."
weight = 12
+++

The `sdme fs build` command creates custom root filesystems from a
simple build config. The config format uses `FROM`, `RUN`, and `COPY`
directives, similar to a Dockerfile. Each `RUN` step executes inside
a booted systemd-nspawn container, so you get a real systemd
environment with working package managers, services, and networking.

Builds are resumable: if a `RUN` step fails, re-running the same
command picks up where it left off. Use `--no-cache` to start fresh.

## Prerequisites

You need a base rootfs to build from. If you don't have one:

```sh
sudo sdme fs import ubuntu docker.io/ubuntu
```

## FROM

Every build config starts with a `FROM` directive that specifies the
base rootfs:

```
FROM ubuntu
```

## RUN

`RUN` executes a shell command inside the container via `/bin/sh -c`.
Pipes, `&&`, and other shell constructs work normally:

```
FROM ubuntu
RUN apt update && apt install -y curl git
```

Long commands can be split across lines with a trailing backslash:

```
FROM ubuntu
RUN apt update && \
    apt install -y curl git make
```

## COPY

`COPY` writes files into the rootfs. The source can be the host
filesystem, another rootfs, or a running container.

### From host (no prefix)

Copy a file or directory from the host into the rootfs:

```
COPY ./myconfig.conf /etc/myapp/config.conf
COPY ./scripts /usr/local/bin
```

### From another rootfs (fs: prefix)

Copy from an imported rootfs using `fs:<name>:<path>`. This is how
multi-stage builds work: compile in a builder rootfs, then copy just
the binary into a clean runtime rootfs.

```
COPY fs:builder:/usr/local/bin/myapp /usr/local/bin/myapp
```

### From a running container (name:path)

Copy from a running container by name. The container must be running
when the build executes this step.

For example, if you have a container called `configgen` that
generates configuration files at boot:

```
COPY configgen:/etc/generated.conf /etc/app/generated.conf
```

Each COPY directive takes exactly one source and one destination.
Globs and multiple sources are not supported.

## Putting it together

A two-stage build that compiles a Go program in a builder rootfs
and copies the binary into a minimal runtime:

Stage 1 (`builder.sdme`):

```
FROM ubuntu
RUN apt update && apt install -y golang git
RUN git clone https://example.com/myapp /usr/src/myapp
RUN cd /usr/src/myapp && go build -o /usr/local/bin/myapp .
```

```sh
sudo sdme fs build builder ./builder.sdme
```

Stage 2 (`runtime.sdme`):

```
FROM ubuntu
RUN apt update && apt install -y ca-certificates
COPY fs:builder:/usr/local/bin/myapp /usr/local/bin/myapp
```

```sh
sudo sdme fs build runtime ./runtime.sdme
```

## Reference

See `sdme fs build --help` for the full reference, including
resumable builds, cache invalidation, and COPY source prefixes.
