+++
title = "Intro to Running OCI Applications"
description = "Import and run OCI application images like nginx as systemd services inside sdme containers."
weight = 6
+++

This tutorial shows how to import an OCI application image (nginx) and
run it inside an sdme container.

## Base OS vs application images

When importing an OCI image, sdme classifies it as either a **base OS**
or an **application**:

- **Base OS** images (ubuntu, debian, fedora) are extracted as a
  standalone sdme rootfs. They contain a full Linux distribution you
  can boot into.
- **Application** images (nginx, redis, postgres) have an entrypoint,
  commands, or exposed ports. sdme places them as a systemd service
  inside a base OS rootfs.

This detection is automatic. Application images require a base rootfs
to run inside, specified with `--base-fs`.

## How it works

The container always boots from the base OS rootfs (e.g. Ubuntu).
The application image (e.g. nginx, which may be Alpine-based
internally) is placed under `/oci/apps/{name}/root` and runs as a
chrooted systemd service inside that container. The application is
isolated with its own PID and IPC namespaces, just as it would expect
in a traditional container runtime. For more details, see the
[OCI integration](@/docs/architecture.md#16-oci-integration)
architecture and
[OCI app isolation](@/docs/security.md#13-oci-app-isolation-architecture)
security documentation.

<pre class="diagram">
+--------------------------------------------------+
|            sdme container (nspawn)               |
|                                                  |
|  systemd . journald . D-Bus                      |
|                                                  |
|  +--------------------------------------------+  |
|  |  sdme-oci-nginx.service                    |  |
|  |  RootDirectory=/oci/apps/nginx/root        |  |
|  |                                            |  |
|  |  +--------------------------------------+  |  |
|  |  |           nginx process              |  |  |
|  |  +--------------------------------------+  |  |
|  +--------------------------------------------+  |
|                                                  |
|  /oci/apps/nginx/env      (environment vars)     |
|  /oci/apps/nginx/ports    (exposed ports)        |
|  /oci/apps/nginx/volumes  (declared volumes)     |
+--------------------------------------------------+
</pre>

The application runs as a regular systemd service. You get logs via
`journalctl`, restarts via `systemctl`, and cgroup resource limits,
all for free.

## Import nginx

First, make sure you have a base rootfs imported. If not:

```sh
sudo sdme fs import ubuntu docker.io/ubuntu
```

Then import nginx on top of it:

```sh
sudo sdme fs import nginx docker.io/nginx --base-fs ubuntu
```

To avoid repeating `--base-fs` on every import, set a default:

```sh
sudo sdme config set default_base_fs ubuntu
```

## Create and start the container

We recommend using `--network-zone` and `--hardened` as described
in the [services tutorial](@/tutorial/services.md):

```sh
sudo sdme create mycontainer -r nginx --network-zone=services --hardened
sudo sdme start mycontainer
```

This gives the container its own network with DNS and user namespace
isolation. Find the container's IP with `sdme ps`:

```sh
sudo sdme ps
```

Then from the host, use the ADDRESSES column to reach nginx:

```sh
curl http://<container-ip>
```

You should see the nginx welcome page.

## View logs

From the host, you can check the OCI application logs:

```sh
sudo sdme logs mycontainer --oci
```

This is equivalent to running `journalctl -u sdme-oci-nginx` inside
the container. Replace `mycontainer` with your container's name.

## Enter the OCI application

To get a shell inside the nginx chroot (not the container's base OS):

```sh
sudo sdme join mycontainer --oci
```

This drops you into the nginx rootfs at `/oci/apps/nginx/root`.
