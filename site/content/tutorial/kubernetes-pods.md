+++
title = "Running Kubernetes Pods"
description = "Deploy multi-container applications from standard Kubernetes Pod YAML manifests."
weight = 11
+++

sdme can create containers from Kubernetes Pod YAML manifests. This
is not the same as the [sdme pod](@/tutorial/pod-networking.md)
networking feature. Kubernetes Pod YAML describes a complete
multi-container application (images, environment variables, volumes,
probes) in a single file that sdme parses and deploys.

See also the [architecture documentation](@/docs/architecture.md#17-kubernetes-pod-support)
for implementation details.

## How it works

`sdme kube apply` reads a Pod (or Deployment) YAML, pulls the
specified OCI images, builds a combined rootfs on a base OS, and
starts a single nspawn container with one systemd service per
application container. All containers in the pod share localhost,
just like in Kubernetes.

## A simple example

Create a file called `redis-pod.yaml`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-redis
spec:
  containers:
  - name: redis
    image: docker.io/redis:latest
```

Deploy it:

```sh
sudo sdme kube apply -f redis-pod.yaml --base-fs ubuntu
```

This pulls the redis image, builds a rootfs called `kube-my-redis`
on top of the ubuntu base, starts the container, and drops you into
a shell.

Check the redis service:

```sh
sudo sdme logs my-redis --oci redis
```

{% callout(type="warn", title="Image names must be fully qualified") %}
sdme requires the full registry prefix in image names (e.g. `docker.io/redis:latest`, not just `redis`). Standard Kubernetes specs that use short names need to be updated with the registry prefix.
{% end %}

## Multi-container pod

A pod can run multiple containers that communicate over localhost.
Create `web-pod.yaml`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-web
spec:
  containers:
  - name: nginx
    image: docker.io/nginx:latest
  - name: redis
    image: docker.io/redis:latest
```

```sh
sudo sdme kube apply -f web-pod.yaml --base-fs ubuntu
```

Inside the pod, nginx runs on port 80 and redis on port 6379,
both reachable via `127.0.0.1`.

## Environment variables

Pass configuration to containers via `env`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-db
spec:
  containers:
  - name: postgres
    image: docker.io/postgres:latest
    env:
    - name: POSTGRES_PASSWORD
      value: "secret"
```

## Create without entering

Use `sdme kube create` to build the pod without starting it or
dropping into a shell:

```sh
sudo sdme kube create -f redis-pod.yaml --base-fs ubuntu
```

Then start and manage it with the usual commands:

```sh
sudo sdme start my-redis
sudo sdme logs my-redis --oci redis
sudo sdme stop my-redis
```

## Deleting a kube pod

`sdme kube delete` stops and removes both the container and its
generated rootfs:

```sh
sudo sdme kube delete my-redis
```

## Setting a default base rootfs

To avoid repeating `--base-fs` on every kube command:

```sh
sudo sdme config set default_base_fs ubuntu
```

Then `--base-fs` can be omitted:

```sh
sudo sdme kube apply -f redis-pod.yaml
```

## What's supported

sdme supports a subset of the Kubernetes Pod spec:

- Multiple containers per pod (shared localhost)
- Environment variables (`env`, `envFrom`)
- Secrets and ConfigMaps (`sdme kube secret`, `sdme kube configmap`)
- Volumes: emptyDir, hostPath, secret, configMap, persistentVolumeClaim
- Health probes: startup, liveness, readiness (exec, HTTP, TCP, gRPC)
- Container command/args (Kubernetes semantics: command overrides
  entrypoint, args overrides cmd)
- Restart policies (Always, OnFailure, Never)
- Security context at the pod and container level
- Deployments (extracts the pod template)

For the full list of supported fields, see `sdme kube apply --help`.
