+++
title = "Bind Mounts and OCI Volumes"
description = "Share files between host and containers using bind mounts and OCI volumes."
weight = 6
+++

Bind mounts let you share directories between the host and a container.
This is useful for serving content you're actively editing, sharing
configuration files, or persisting data outside the container. See
also the [architecture documentation](https://github.com/fiorix/sdme/blob/main/docs/architecture.md#11-bind-mounts-and-environment-variables).

## Bind mounts with a regular service

Building on the [running long-lived services](/tutorial/services/)
tutorial, create a directory on the host with some content:

```sh
mkdir -p /tmp/mysite
echo '<h1>Hello from sdme</h1>' > /tmp/mysite/index.html
```

Create a container with a bind mount mapping that directory into
nginx's document root as a subdirectory:

```sh
sudo sdme new mywebserver -r fedora -b /tmp/mysite:/usr/share/nginx/html/example
```

Inside the container, install and start nginx:

```sh
dnf install -y nginx
systemctl enable --now nginx
```

From the host, verify:

```sh
curl http://localhost/example/
```

Note the trailing slash: without it, nginx returns a redirect error.

You should see "Hello from sdme". Now edit the file on the host:

```sh
echo '<h1>Updated content</h1>' > /tmp/mysite/index.html
```

Curl again and the change is immediately visible, no restart needed.
The default nginx page at `http://localhost` is unaffected.

{% callout(type="tip", title="Tip") %}
We bind-mount to a subdirectory (`example/`) rather than replacing the entire HTML root. Replacing it can conflict with the default nginx installation on some distros (e.g. Fedora's `index.html` is a symlink that breaks when the directory is overlaid).
{% end %}

Append `:ro` to make a bind mount read-only (e.g. `-b /host/path:/container/path:ro`).
Avoid mounting over system directories like `/etc` or `/usr` as it
can break the container. See `sdme new --help` for the full syntax.

## Bind mounts with an OCI application

When using an OCI application, the app runs chrooted under
`/oci/apps/{name}/root` inside the container. Bind mount paths need
to target that prefix.

Following the [OCI tutorial](/tutorial/oci-apps/), after importing nginx with
`sudo sdme fs import nginx docker.io/nginx --base-fs ubuntu`, you
can bind-mount a host directory to the nginx HTML root:

```sh
sudo sdme create mywebserver -r nginx -b /tmp/mysite:/oci/apps/nginx/root/usr/share/nginx/html
sudo sdme start mywebserver
sudo sdme ps
```

From the host:

```sh
curl http://localhost
```

The same content from `/tmp/mysite` is served by nginx.

Here we use `create` and `start` separately to show the two-step
process. You can also use `sdme new` which combines both and drops
you into a shell.

## OCI auto-volumes

Some OCI images declare volumes (like Docker's `VOLUME` directive).
When sdme imports an OCI app that declares volumes, it automatically
creates host-side directories and bind-mounts them into the container
at creation time.

You can check if an imported OCI rootfs declares any volumes:

```sh
cat /var/lib/sdme/fs/{name}/oci/apps/{app}/volumes
```

If volumes are declared, sdme creates a host directory for each one
at `/var/lib/sdme/volumes/{container}/{sanitized-path}` and
bind-mounts it into the container.

### Volume data persistence

Volume data survives container removal. When you run `sdme rm`, it
prints the volume path but does not delete the data. This means you
can recreate a container and the volume data is still there.

### Overriding auto-volumes

Your `--bind` flags take priority over auto-volumes. If you bind-mount
to the same container path that an auto-volume would use, the
auto-volume is skipped.

To suppress auto-volumes entirely, use `--no-oci-volumes`.
