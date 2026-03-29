+++
title = "Network Configuration"
description = "Configure container networking: host network, private network, veth, zones, bridges, and port forwarding."
weight = 9
+++

sdme containers share the host network by default. This tutorial
covers all available network modes, from full isolation to
multi-container networking.

See also the [architecture documentation](@/docs/architecture.md#9-networking)
for implementation details.

## Host network (default)

With no network flags, containers share the host's network namespace.
They see the same interfaces, addresses, and routes. Services bind
to the same ports as the host.

This is the simplest mode but means port conflicts are possible.
Use `--network-zone` or `--network-veth` to avoid them.

## Private network

```sh
sudo sdme new mybox -r ubuntu --private-network
```

The container gets its own network namespace with only a loopback
interface. No external connectivity, no internet. Useful for fully
isolated workloads that don't need networking.

## Virtual ethernet (veth)

```sh
sudo sdme new mybox -r ubuntu --network-veth
```

Creates a virtual ethernet link between the host and the container.
The container gets an interface named `host0` with an IP assigned
via DHCP. The container can reach the host and the internet.

sdme automatically enables `systemd-networkd` inside the container
so the `host0` interface gets configured via DHCP. No manual setup
needed.

`--network-veth` implies `--private-network`.

## Port forwarding

Port forwarding maps a host port to a container port. It requires
a network interface, so you must use `--network-veth`,
`--network-bridge`, or `--network-zone` alongside `--port`.

```sh
sudo sdme new myweb -r nginx --network-veth --port 8080:80
```

This forwards host port 8080 to container port 80. Format:

<pre class="diagram">
--port HOST:CONTAINER
--port HOST:CONTAINER/tcp
--port HOST:CONTAINER/udp
</pre>

Multiple `--port` flags can be used. TCP is the default protocol.

## Zones

Zones are the easiest way to set up multi-container networking.
Containers on the same zone share a bridge and can communicate
with each other by IP or hostname.

```sh
sudo sdme new http-server -r nginx --network-zone=myzone
```

```sh
sudo sdme new http-client -r ubuntu --network-zone=myzone
```

Both containers get DHCP addresses on the zone bridge. sdme
automatically:

- Creates the zone bridge (no host setup needed)
- Enables `systemd-networkd` inside each container
- Unmasks `systemd-resolved` and configures LLMNR/mDNS so
  containers can discover each other by hostname

From inside `http-client`, you can reach `http-server` by name:

```sh
curl http://http-server
```

Port forwarding works with zones:

```sh
sudo sdme new myweb -r nginx --network-zone=myzone --port 8080:80
```

`--network-zone` implies `--private-network`.

## Bridges

Bridges connect containers to a manually configured host bridge.
Unlike zones, you must create and configure the bridge yourself.

Create a bridge on the host:

```sh
sudo ip link add sdmebr0 type bridge
sudo ip addr add 10.99.0.1/24 dev sdmebr0
sudo ip link set sdmebr0 up
```

Create containers on the bridge:

```sh
sudo sdme create server -r nginx --network-bridge=sdmebr0
```

Containers on a bridge need static IP configuration. Write a
networkd config to the container's overlayfs upper layer before
starting:

```sh
sudo tee /var/lib/sdme/containers/server/upper/etc/systemd/network/10-bridge.network <<EOF
[Match]
Name=host0

[Network]
Address=10.99.0.2/24
DNS=10.99.0.1
EOF
```

```sh
sudo sdme start server
```

`--network-bridge` implies `--private-network`.

{% callout(type="tip", title="Tip") %}
Zones are simpler than bridges for most use cases. Use bridges when you need to integrate containers with an existing host bridge or require static IP assignments.
{% end %}

## DNS and resolved

By default, sdme masks `systemd-resolved.service` inside containers
that use host networking. This prevents the container's resolved
from conflicting with the host's DNS on port 53.

When using `--network-veth`, `--network-zone`, or `--network-bridge`,
sdme automatically unmasks resolved and symlinks `/etc/resolv.conf`
to the resolved stub so DNS works inside the container.

Zones additionally configure LLMNR/mDNS for inter-container hostname
discovery.

You can override the masking behavior with `--masked-services`:

Mask resolved explicitly (even with a zone):

```sh
sudo sdme new mybox -r ubuntu --network-zone=myzone --masked-services systemd-resolved.service
```

Disable all masking:

```sh
sudo sdme new mybox -r ubuntu --masked-services=''
```

The default masked services are controlled by the
`default_create_masked_services` config key.

## Summary

<pre class="diagram">
Mode             Flag                Internet  Multi-container  Setup
---------------  ------------------  --------  ---------------  ----------
Host (default)   (none)              Yes       Shared ports     None
Private          --private-network   No        No               None
Veth             --network-veth      Yes       No               None
Zone             --network-zone=X    Yes       Yes (auto DNS)   None
Bridge           --network-bridge=X  Yes       Yes (manual IP)  Host bridge
</pre>

Port forwarding (`--port`) works with veth, zone, and bridge modes.
