+++
title = "Multi-Container Pod Networking"
description = "Share a network namespace between containers so they communicate via localhost."
weight = 10
+++

Pods let multiple containers share a network namespace, so they can
communicate over `127.0.0.1` without any port forwarding or bridge
configuration. This is the same model used by Kubernetes pods.

See also the [architecture documentation](@/docs/architecture.md#10-pods)
for implementation details.

## Creating a pod

```sh
sudo sdme pod new mypod
```

This creates an isolated network namespace with only a loopback
interface. Containers that join the pod share this namespace and
can reach each other on localhost.

List and remove pods:

```sh
sudo sdme pod ls
```

```sh
sudo sdme pod rm mypod
sudo sdme pod rm -a       # remove all pods
sudo sdme pod rm -a -f    # force: also stop and remove attached containers
```

## Example: nginx and curl via --pod

The `--pod` flag puts the entire container into the pod's network
namespace. All processes inside the container share it.

Create a pod and two containers. We use the OCI nginx rootfs (from
the [OCI tutorial](@/tutorial/oci-apps.md)) since pod containers
only have loopback and cannot download packages.

```sh
sudo sdme pod new webpod
```

Start an nginx server in the pod:

```sh
sudo sdme create http-server -r nginx --pod webpod
sudo sdme start http-server
```

Start a client in the same pod and drop into a shell. The client
uses a host clone which already has curl:

```sh
sudo sdme new http-client --pod webpod
```

Inside the client, curl the server via localhost:

```sh
curl localhost
```

You should see the nginx welcome page. Both containers share the
same loopback interface.

You can see both containers and their pod association with:

```sh
sudo sdme ps
```

The POD column shows which pod each container belongs to.

### Limitations of --pod

Pod network namespaces start with only a loopback interface. Without
external networking, containers in a pod cannot reach the internet,
download packages, or communicate with anything outside the pod.

To add external connectivity, use `sdme pod net attach`:

```sh
sudo sdme pod net attach webpod veth
```

This creates a veth pair between the pod and the host. The host's
systemd-networkd handles DHCP and NAT automatically. See the
[external connectivity](#external-connectivity) section below.

Without external networking, install any software you need before
joining the pod, or use pre-built OCI rootfs images.

`--pod` works with `--userns`, `--hardened`, and `--strict`. The
container is launched via `nsenter --net=` so the pod's network
namespace is entered before nspawn creates the user namespace.

## Example: redis via --oci-pod

The `--oci-pod` flag is for OCI application containers. Only the OCI
app service process enters the pod's network namespace; the
container's init and other services remain in their own namespace.

This works with `--hardened` and `--strict` because the network
namespace join happens inside the container's own namespace.

Create a pod and import redis:

```sh
sudo sdme pod new dbpod
```

```sh
sudo sdme fs import redis docker.io/redis --base-fs ubuntu
```

Start redis in the pod with hardened security:

```sh
sudo sdme create redis-server -r redis --oci-pod dbpod --hardened
sudo sdme start redis-server
```

Verify redis is running:

```sh
sudo sdme logs redis-server --oci
```

Start a client container in the same pod using the same redis
rootfs, so `redis-cli` is available. Both containers use
`--oci-pod` with `--hardened`:

```sh
sudo sdme create redis-client -r redis --oci-pod dbpod --hardened
sudo sdme start redis-client
```

Test the connection from the client:

```sh
sudo sdme exec redis-client --oci -- redis-cli ping
```

You should see `PONG`. Both containers share the pod's network
namespace and communicate over localhost, each running with
hardened security.

## --pod vs --oci-pod

<pre class="diagram">
Feature            --pod                  --oci-pod
-----------------  ---------------------  -------------------------
Scope              Entire container       OCI app service only
Container types    Any                    OCI app rootfs required
Userns/hardened    Compatible             Compatible
Requires           (nothing extra)        --private-network or
                                          --hardened/--strict
Use case           General-purpose pods   Security-hardened apps
</pre>

Both flags can be used on different containers in the same pod.
The pod's network namespace is shared regardless of which flag
each container uses to join it.

## External connectivity

Pods start with loopback-only networking. Use `pod net attach` to
give containers in a pod internet access.

Requires: iproute2 (`ip`), dhcpcd.

### Veth mode

Creates a point-to-point veth between the pod and the host:

```sh
sudo sdme pod new mypod
sudo sdme new mybox --pod mypod
sudo sdme start mybox
sudo sdme pod net attach mypod veth
```

Test connectivity from inside the container:

```sh
sudo sdme exec mybox -- ping -c1 8.8.8.8
```

Detach when no longer needed:

```sh
sudo sdme pod net detach mypod
```

### Zone mode

Connects the pod to a named zone bridge. Multiple pods and regular
containers on the same zone can reach each other directly:

```sh
sudo sdme pod new pod1
sudo sdme pod new pod2
sudo sdme pod net attach pod1 zone myzone
sudo sdme pod net attach pod2 zone myzone
```

Containers in pod1 and pod2 can now communicate through the
`vz-myzone` bridge, and both have internet access.

### How it works

The host's systemd-networkd handles everything: DHCP serving, NAT
(IPMasquerade), and IP forwarding. sdme creates the veth pair with
interface names that match nspawn conventions (`ve-*`, `vb-*`,
`vz-*`), so networkd's default configs apply automatically.

A host-managed systemd service (`sdme-pod-net@{pod}.service`) runs
dhcpcd inside the pod's netns using `NetworkNamespacePath=`. The
host's systemd manages the DHCP client lifecycle.

DNS servers from the DHCP lease are extracted and written to each
container's `/etc/resolv.conf` (for `--pod`) or each OCI app's
chroot resolv.conf (for `--oci-pod`). Running containers are
updated immediately on attach and detach.

Attach and detach are live operations: running containers see the
interface appear or disappear immediately. Both `--pod` and
`--oci-pod` containers work because they share the same netns.

After a reboot, networking is automatically restored when the first
container referencing the pod starts.

### Listing pod networking

```sh
sudo sdme pod ls
```

The NET column shows the networking mode and IP addresses, e.g.
`veth (10.0.0.2)` or `zone (10.0.0.3)`, or is empty for
loopback-only pods. Use `--json` or `--json-pretty` for structured
output including container membership.

### Zone interop with regular containers

Pods using zone mode share the same bridge as regular containers
using `--network-zone`. They can reach each other directly:

```sh
sudo sdme pod new mypod
sudo sdme pod net attach mypod zone myzone
sudo sdme new mybox --pod mypod

sudo sdme new standalone -r ubuntu --network-zone myzone
```

Both `mybox` (in the pod) and `standalone` (regular container) are
on the `vz-myzone` bridge and can communicate.

### Creating a pod with networking

Use `--attach` to combine pod creation and network attachment:

```sh
sudo sdme pod new mypod --attach veth
sudo sdme pod new mypod --attach zone --zone myzone
```
