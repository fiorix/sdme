+++
title = "Running Kubernetes Pods"
description = "Deploy OCI applications from Kubernetes Pod YAML manifests."
weight = 11
+++

sdme can create containers from Kubernetes Pod YAML manifests. This
is not the same as the [sdme pod](@/tutorial/pod-networking.md)
networking feature. Kubernetes Pod YAML describes one or more OCI
images to run as isolated services (environment variables, volumes,
probes) in a single file that sdme parses and deploys.

See also the [architecture documentation](@/docs/architecture.md#17-kubernetes-pod-support)
for implementation details.

## How it works

`sdme kube apply` reads a Pod (or Deployment) YAML, pulls the
specified OCI images, builds a combined rootfs on a base OS, and
starts a single nspawn container with one systemd service per OCI
image. All services in the pod share localhost, just like in
Kubernetes.

## A simple example

Create a file called `nginx-pod.yaml`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-nginx
spec:
  containers:
  - name: nginx
    image: nginx
```

Deploy it:

```sh
sudo sdme kube apply -f nginx-pod.yaml --base-fs ubuntu --hardened --network-zone=kube
```

This pulls the nginx image, builds a rootfs called `kube-my-nginx`
on top of the ubuntu base, starts the container with user namespace
isolation and its own network, and drops you into a shell.

Inside the container, you can verify the nginx service with standard
systemd commands:

```sh
systemctl status sdme-oci-nginx.service
journalctl -u sdme-oci-nginx.service
```

Exit the shell with `Ctrl+D` — the container keeps running. From
the host, you can still check the logs:

```sh
sudo sdme logs my-nginx --oci nginx
```

{% callout(type="tip", title="Image registry") %}
Short image names like `redis` or `nginx` are resolved using the `default_kube_registry` config (default: `docker.io`). Fully qualified names like `quay.io/nginx/nginx-unprivileged` are used as-is. To use a different default registry: `sudo sdme config set default_kube_registry registry.example.com`
{% end %}

## Reaching kube pods from other containers

All containers on the same network zone can reach each other by
hostname. Create a regular Arch Linux container on the `kube` zone
and curl the nginx pod:

```sh
sudo sdme new myclient -r archlinux --hardened --network-zone=kube
```

Inside the client container:

```sh
curl http://my-nginx
```

This works because `--network-zone` uses LLMNR for automatic
hostname discovery between containers in the same zone. Any sdme
container — kube or regular — can join the zone and communicate
with the others.

## Multi-service pod

A pod can run multiple OCI services that communicate over localhost.
Create `web-pod.yaml`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-web
spec:
  containers:
  - name: nginx
    image: nginx
  - name: redis
    image: redis
```

```sh
sudo sdme kube apply -f web-pod.yaml --base-fs ubuntu --hardened --network-zone=kube
```

Inside the container, nginx runs on port 80 and redis on port 6379,
both reachable via `127.0.0.1`.

## Environment variables

Pass configuration to OCI services via `env`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-db
spec:
  containers:
  - name: postgres
    image: postgres
    env:
    - name: POSTGRES_PASSWORD
      value: "secret"
```

## Create without entering

Use `sdme kube create` to build the pod without starting it or
dropping into a shell:

```sh
sudo sdme kube create -f nginx-pod.yaml --base-fs ubuntu --hardened --network-zone=kube
```

Then start and manage it with the usual commands:

```sh
sudo sdme start my-nginx
sudo sdme logs my-nginx --oci nginx
sudo sdme stop my-nginx
```

## Deleting a kube pod

`sdme kube delete` stops and removes both the container and its
generated rootfs:

```sh
sudo sdme kube delete my-nginx
```

## Setting a default base rootfs

To avoid repeating `--base-fs` on every kube command:

```sh
sudo sdme config set default_base_fs ubuntu
```

Then `--base-fs` can be omitted:

```sh
sudo sdme kube apply -f nginx-pod.yaml --hardened --network-zone=kube
```

## Networking

All examples in this tutorial use `--network-zone=kube`, which
gives each container its own network namespace with automatic DNS
between containers in the same zone. Containers are reachable by
IP from the host (use `sdme ps` to find the address).

The Kubernetes `hostNetwork: true` field is supported and keeps the
container on the host network.

See the [network configuration](@/tutorial/networking.md) tutorial
for details on each mode.

## What's supported

sdme supports a subset of the Kubernetes Pod spec:

- Multiple OCI services per pod (shared localhost)
- Environment variables (`env`, `envFrom`)
- Secrets and ConfigMaps (`sdme kube secret`, `sdme kube configmap`)
- Volumes: emptyDir, hostPath, secret, configMap, persistentVolumeClaim
- Health probes: startup, liveness, readiness (exec, HTTP, TCP, gRPC)
- Container command/args (Kubernetes semantics: command overrides
  entrypoint, args overrides cmd)
- Restart policies (Always, OnFailure, Never)
- Networking: `hostNetwork`, `--network-veth`, `--network-zone`,
  `--network-bridge`, `--port`
- Security context at the pod and container level
- Deployments (extracts the pod template)

For the full list of supported fields, see `sdme kube apply --help`.
