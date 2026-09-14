# Documentation

Guides and reference for sdme, the systemd machine editor. Read these files here on GitHub or on [sdme.io](https://sdme.io/).

For installation, see the [project README](../README.md#installation).

## Reference

- [Architecture and Design](architecture.md): How sdme works: overlayfs, systemd integration, OCI support, and Kubernetes pods.
- [Security](security.md): Container isolation, hardening tiers, OCI workload security, and Kubernetes pod security.
- [AI Skill](ai-skill.md): Embedded AI agent skill for using and troubleshooting sdme.

## Tutorials

- [Using sdme on macOS](tutorial/macos.md): Set up a Linux VM with lima-vm to run sdme on your Mac.
- [Using sdme on Windows](tutorial/windows.md): Run sdme inside WSL 2 on Windows.
- [Your First Container](tutorial/first-container.md): Create a container, manage it, and learn how to run background processes like tmux.
- [Using a Different Root Filesystem](tutorial/different-rootfs.md): Import other Linux distributions and create containers from them.
- [Day-to-Day Management](tutorial/management.md): Essential commands for managing containers: listing, logs, copying files, and troubleshooting.
- [Running Long-Lived Services](tutorial/services.md): Install and run services like nginx inside sdme containers.
- [Intro to Running OCI Applications](tutorial/oci-apps.md): Import and run OCI application images like nginx as systemd services inside sdme containers.
- [Bind Mounts and OCI Volumes](tutorial/bind-mounts-volumes.md): Share files between host and containers using bind mounts and OCI volumes.
- [Running an OCI Database with Volumes](tutorial/oci-volumes.md): Run PostgreSQL with automatically managed OCI volumes that persist data across container removal and re-creation.
- [Network Configuration](tutorial/networking.md): Configure container networking: host network, private network, veth, zones, bridges, and port forwarding.
- [Multi-Container Pod Networking](tutorial/pod-networking.md): Share a network namespace between containers so they communicate via localhost.
- [Running Kubernetes Pods](tutorial/kubernetes-pods.md): Deploy OCI applications from Kubernetes Pod YAML manifests.
- [Building Root Filesystems](tutorial/building-rootfs.md): Build custom root filesystems with sdme fs build using Dockerfile-like configs.
- [Running Docker and a Registry Inside a Container](tutorial/docker-in-container.md): Run a full Docker engine and a private registry inside an sdme container, backed by btrfs storage.
