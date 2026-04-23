//! CLI entry point for sdme.
//!
//! Parses command-line arguments via clap and dispatches to the
//! appropriate library function.

use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use sdme::import::{ImportOptions, InstallPackages, OciMode};
use sdme::{
    check_interrupted, config, confirm, containers, cp, export, kube, oci, pod, prune, rootfs,
    security, system_check, systemd,
};

mod cli;
use cli::*;

// ---------------------------------------------------------------------------
// Help text constants (referenced by #[command(after_long_help = ...)])
// ---------------------------------------------------------------------------

const CLI_HELP: &str = "\
sdme boots systemd-nspawn containers using overlayfs copy-on-write layers.
Each container gets its own upper layer; the base rootfs stays untouched.
By default, the host root filesystem is used as the base layer. Other distros
can be imported and used instead.

Requires root. Runs on Linux with systemd >= 255.

GETTING STARTED:
    # Clone the host as a throwaway container
    sdme new

    # Import Ubuntu from Docker Hub and create a named container
    sdme fs import ubuntu docker.io/ubuntu -v --install-packages=yes
    sdme new mybox -r ubuntu

    # Run an OCI application image (nginx) on top of ubuntu
    sdme fs import nginx docker.io/nginx --base-fs=ubuntu -v
    sdme new -r nginx

COMMON COMMANDS:
    sdme ps                 List containers
    sdme join <name>        Enter a running container
    sdme exec <name> CMD    Run a command in a running container
    sdme cp SRC DST         Copy files between host and containers
    sdme stop <name>        Stop a container
    sdme restart <name>     Restart a running container
    sdme rm <name>          Remove a container
    sdme logs <name>        View container logs
    sdme fs ls              List imported root filesystems
    sdme config get         Show configuration

ENVIRONMENT:
    SUDO_USER           When set, 'join' and 'exec' run as this user (see
                        join_as_sudo_user config key)
    https_proxy, ...    HTTP proxy for downloads (pass through sudo with -E)
    no_proxy            Hosts that bypass the proxy

FILES:
    /etc/sdme.conf                          Configuration file (TOML)
    /var/lib/sdme/fs/<name>/                Imported root filesystems
    /var/lib/sdme/state/<name>              Container state files (KEY=VALUE)
    /var/lib/sdme/containers/<name>/        Overlayfs upper/work/merged dirs
    /var/lib/sdme/volumes/<name>/           OCI volume data (survives rm)
    /var/lib/sdme/pods/<name>/state         Pod state files
    /var/lib/sdme/secrets/<name>/data/      Kube secret data (mode 0600)
    /var/lib/sdme/configmaps/<name>/data/   Kube configmap data
    /etc/systemd/system/sdme@.service       Template unit (auto-managed)

EXIT STATUS:
    0       Success
    130     Interrupted by Ctrl+C (SIGINT)
    143     Interrupted by SIGTERM

NOTES:
    Container creation requires a permissive umask (default 022 is fine).
    Restrictive umasks (e.g. 077) are rejected because non-root services
    inside the container need to traverse the overlayfs upper layer.

    Ctrl+C during 'new' or 'start' stops the container but preserves it
    on disk for debugging. Batch operations (rm -a, start --all, stop)
    abort immediately; remaining items are not processed.

    Container names support prefix matching: 'sdme stop my' will match
    'mybox' if it is the only container whose name starts with 'my'. An
    exact match always takes priority. Ambiguous prefixes produce an error.";

const NEW_HELP: &str = "\
Create a new container, start it, and open a shell. Accepts the same flags as
'create'. If no name is given, one is generated automatically.

EXAMPLES:
    # Host clone with generated name
    sdme new

    # Named container from imported rootfs
    sdme new mybox -r ubuntu

    # OCI application image with port forwarding (use 'sdme ps' for container IP)
    sdme new web -r nginx --network-veth -p 8080:80

    # Private network with virtual ethernet and resource limits
    sdme new dev -r ubuntu --network-veth --memory 2G --cpus 2

    # Network zone for inter-container DNS
    sdme new node1 -r ubuntu --network-zone myzone
    sdme new node2 -r ubuntu --network-zone myzone

    # Hardened security (userns, private-network, no-new-privileges, cap drops)
    sdme new sandbox -r ubuntu --hardened

    # Strict security (hardened + Docker-equivalent caps, seccomp, AppArmor)
    sdme new jail -r ubuntu --strict

    # Bind mount and environment variable
    sdme new -r ubuntu -b /srv/data:/data:ro -e MYVAR=hello

    # OCI environment variables (set inside the OCI app service)
    sdme new -r nginx --oci-env PORT=8080 --oci-env DEBUG=1

    # Custom boot timeout (seconds)
    sdme new -r ubuntu -t 120

    # Specific shell or command
    sdme new -r ubuntu -- /bin/bash

PORT FORWARDING:
    --port creates nftables DNAT rules for incoming traffic from the
    network and from the host via its external IP, but not via localhost
    (127.0.0.1). To reach a container from the host, use the container's
    IP shown by 'sdme ps'.

OCI AUTO-BEHAVIORS:
    OCI images that declare ports get automatic --port rules when the
    container has a private network. User --port flags take priority.
    Use --no-oci-ports to suppress. On host-network containers, ports
    are informational only.

    OCI images that declare volumes get automatic bind mounts to
    {datadir}/volumes/{container}/{vol}. User --bind flags take priority.
    Use --no-oci-volumes to suppress. Volume data survives 'sdme rm'.

    --oci-env sets env vars for the OCI app service (via EnvironmentFile).
    -e/--env sets env vars for the container's systemd init (via --setenv).

DEBUGGING:
    --systemd-log-level sets SYSTEMD_LOG_LEVEL for the nspawn host
    process (not the container). Useful for diagnosing boot issues.
    Valid values: emerg, alert, crit, err, warning, notice, info, debug.
    Use -e SYSTEMD_LOG_LEVEL=debug for the container's internal systemd.";

const CREATE_HELP: &str = "\
Create a new container without starting it. Use 'sdme start' to start it later,
or pass --started to start immediately.

EXAMPLES:
    # Create from imported rootfs
    sdme create mybox -r ubuntu

    # Create with auto-start on boot
    sdme create mybox -r ubuntu --enable

    # Create and start immediately (removes on start failure)
    sdme create mybox -r ubuntu --started

    # Create and start with custom boot timeout
    sdme create mybox -r ubuntu --started -t 120

    # Join a pod network namespace
    sdme pod new mypod
    sdme create app1 -r nginx --pod mypod
    sdme create app2 -r redis --pod mypod

    # Override default masked services
    sdme create mybox -r ubuntu --masked-services systemd-resolved.service,systemd-timesyncd.service

    # Create with no services masked
    sdme create mybox -r ubuntu --masked-services ''

    # User namespace isolation
    sdme create mybox -r ubuntu --userns

    # Read-only rootfs with dropped capabilities
    sdme create mybox -r ubuntu --read-only --drop-capability CAP_NET_RAW

SERVICE MASKING:
    At create time, services listed in default_create_masked_services are
    masked (symlinked to /dev/null) in the overlayfs upper layer.
    Default: systemd-resolved.service (prevents DNS conflict on host network).
    --masked-services overrides this entirely. An empty value masks nothing.
    With --network-veth, --network-zone, or --network-bridge and no
    explicit --masked-services, resolved is auto-unmasked and enabled
    for DNS. Zone containers also get LLMNR/mDNS for inter-container
    name resolution.
    NixOS rootfs skip masking (activation replaces /etc/systemd/system).";

const STOP_HELP: &str = "\
Three shutdown tiers, in order of escalation:

  Default (graceful):  Sends SIGRTMIN+4 to the container leader, which
                       tells systemd-nspawn to initiate a clean shutdown.
                       Timeout: stop_timeout_graceful (default 90s).

  --term (terminate):  Sends SIGTERM to the nspawn leader via TerminateMachine.
                       Timeout: stop_timeout_terminate (default 30s).

  --kill (force-kill): Sends SIGKILL to all container processes via KillMachine.
                       Timeout: stop_timeout_kill (default 15s).

--term and --kill are mutually exclusive. Timeouts are configurable via
'sdme config set'.

EXAMPLES:
    sdme stop mybox
    sdme stop mybox --term
    sdme stop mybox --kill
    sdme stop --all";

const RESTART_HELP: &str = "\
Stop and then start one or more containers. Combines the flags from
'stop' (--term, --kill) and 'start' (--timeout).

EXAMPLES:
    sdme restart mybox
    sdme restart mybox --term
    sdme restart --all
    sdme restart mybox -t 120";

const JOIN_HELP: &str = "\
Open an interactive shell inside a running container via machinectl.

EXAMPLES:
    # Enter with the default login shell
    sdme join mybox

    # Start the container first if it is stopped
    sdme join mybox --start

    # Run a specific shell
    sdme join mybox -- /bin/bash

    # Enter the OCI app's PID/IPC/mount namespaces
    sdme join mybox --oci

    # Target a specific app in a multi-container kube pod
    sdme join mypod --oci nginx";

const EXEC_HELP: &str = "\
Run a one-off command inside a running container via machinectl.
The exit status of the command is forwarded.

EXAMPLES:
    sdme exec mybox -- cat /etc/os-release
    sdme exec mybox -- apt-get update

    # Enter the OCI app's PID/IPC/mount namespaces
    sdme exec mybox --oci -- ls /app

    # Target a specific app in a multi-container kube pod
    sdme exec mypod --oci redis -- redis-cli ping";

const PS_HELP: &str = "\
List all containers with status, health, and configuration summary.

The text table shows fixed columns: NAME, STATUS, HEALTH, USERNS,
ENABLED, MOUNTS, ADDRESSES, and OS. For full details (bind mount specs,
OCI apps with env/ports/volumes, network config, resource limits,
submounts, kube metadata, pod membership, rootfs), use --json or
--json-pretty.

The default output format can be set with:
    sdme config set default_output_format json

See also: sdme fs ls (list root filesystems and their containers).

EXAMPLES:
    sdme ps
    sdme ps --json
    sdme ps --json-pretty
    sdme ps --json | jq '.[] | select(.status == \"running\")'
    sdme config set default_output_format json-pretty";

const LOGS_HELP: &str = "\
View container logs via journalctl inside the container. Extra arguments
are passed through to journalctl.

EXAMPLES:
    sdme logs mybox
    sdme logs mybox -- -f
    sdme logs mybox -- -n 100
    sdme logs mybox -- --since '5 min ago'

    # Show OCI app service logs
    sdme logs mybox --oci

    # Target a specific app in a multi-container kube pod
    sdme logs mypod --oci nginx";

const CP_HELP: &str = "\
Copy files between host, containers, and root filesystems.

Paths inside containers and rootfs must be absolute. Host paths may be
relative or absolute. Copies are always recursive (no -r flag needed).

PATH FORMATS:
    /path or ./path         Host filesystem path
    NAME:/path              Container path (abbreviations supported)
    fs:NAME:/path           Root filesystem path

When the destination is an existing directory, the source is copied into
it (like cp -r). When the source is a directory, its contents are copied
recursively with ownership, permissions, timestamps, and extended
attributes preserved.

RUNNING CONTAINERS:
    Files are read/written through /proc/<leader>/root/, which provides
    access to the container's full mount namespace including tmpfs paths
    (/tmp, /run, /dev/shm). A consistency warning is printed because the
    filesystem may be changing concurrently.

    User namespace containers (--userns, --hardened, --strict) fall back
    to the overlayfs merged/ directory because the kernel blocks /proc/
    root traversal across user namespace boundaries. Paths under /tmp,
    /run, and /dev/shm are not accessible for userns containers; use
    /var/tmp/ as an alternative, or 'sdme exec' to read/write those
    paths directly.

STOPPED CONTAINERS:
    Source reads use a temporary read-only overlay mount. Destination
    writes go directly to the overlayfs upper layer. Writes to /tmp, /run,
    and /dev/shm are refused (systemd mounts tmpfs over them at boot).

LOCKING:
    Shared locks are held on containers and rootfs during the copy to
    prevent concurrent deletion (sdme rm, sdme fs rm). The locks are
    non-blocking: if a deletion is attempted during a copy, it fails
    immediately with a message identifying the holder PID.

ROOT FILESYSTEMS:
    Writes go directly to the rootfs directory. Running containers that
    use this rootfs will NOT see changes (the kernel caches the overlayfs
    lower layer). Stop and restart affected containers to pick up changes.

SAFETY:
    When copying to the host, device nodes are refused by default.
    --force skips all safety checks (device nodes and setuid/setgid warnings).

NOTES:
    Copy behavior (path handling, file type preservation, directory
    semantics) matches 'fs build' COPY directives. The same copy engine
    and path validation are used by both.

EXAMPLES:
    # Copy a file into a container
    sdme cp ./app.conf mybox:/etc/app.conf

    # Copy from container to host
    sdme cp mybox:/etc/os-release .
    sdme cp mybox:/var/log ./logs

    # Copy to/from a root filesystem
    sdme cp ./config fs:ubuntu:/etc/myconfig
    sdme cp fs:ubuntu:/etc/hostname .

EXIT STATUS:
    0       Success
    1       Error
    130     Interrupted by Ctrl+C (SIGINT)
    143     Interrupted by SIGTERM";

const DIFF_HELP: &str = "\
Show filesystem changes in a container's overlayfs upper layer relative to
its base rootfs, or compare changes between two containers.

TARGET FORMATS:
    NAME                Diff container against its base rootfs
    FROM..TO            Diff between two containers' upper layers

PATH FILTERING:
    Paths after '--' restrict output to specific subtrees.

OUTPUT MODES:
    Default             A/M/D status with file path (binary files labeled)
    --stat              Summary statistics (counts by change type)
    --name-only         File paths only, no status prefix

OVERLAYFS DETAILS:
    Each container's upper layer records files that were added, modified,
    or deleted relative to the base rootfs (lower layer). Deleted files
    appear as overlayfs whiteout markers (character devices 0,0). Opaque
    directories (trusted.overlay.opaque xattr) hide all lower content.

EXAMPLES:
    # Show all changes in container 'mybox'
    sdme diff mybox

    # Show only /etc changes
    sdme diff mybox -- /etc

    # Compare two containers
    sdme diff dev..staging

    # Summary statistics
    sdme diff mybox --stat

    # File paths only (for scripting)
    sdme diff mybox --name-only

EXIT STATUS:
    0       Success (or no changes)
    1       Error
    130     Interrupted by Ctrl+C (SIGINT)
    143     Interrupted by SIGTERM";

const FS_HELP: &str = "\
Manage root filesystems used as base layers for containers. Each rootfs is
stored under {datadir}/fs/{name} and used as the lower layer in overlayfs.

SUBCOMMANDS:
    import   Import from a directory, tarball, URL, OCI image, or QCOW2
    ls       List imported root filesystems
    rm       Remove root filesystems
    build    Build a rootfs from a config file (FROM/RUN/COPY)
    export   Export a container or rootfs to a directory, tarball, or disk image
    cache    Manage the OCI blob cache
    gc       Clean up stale staging directories from interrupted operations

The default output format for fs ls can be set with:
    sdme config set default_output_format json

See also: sdme ps (list containers and their rootfs).

EXAMPLES:
    sdme fs import ubuntu docker.io/ubuntu -v --install-packages=yes
    sdme fs import debian /tmp/debootstrap-output
    sdme fs ls
    sdme fs ls --json
    sdme fs rm ubuntu";

const FS_IMPORT_HELP: &str = "\
SUPPORTED SOURCES:
    Directory           Local path containing a root filesystem tree
    Tarball             .tar, .tar.gz, .tar.bz2, .tar.xz, .tar.zst
    URL                 http:// or https:// (downloads, then auto-detects)
    OCI tarball         Tarball containing an oci-layout file
    OCI registry        docker.io/ubuntu, ghcr.io/org/app:v1, etc.
    QCOW2 disk image    Requires qemu-nbd

OCI REGISTRY IMAGES:
    --oci-mode controls how the image is classified:

      auto (default)    Auto-detect from image config. Base OS images have no
                        entrypoint, a shell as default command, and no exposed
                        ports. Everything else is an application image.

      base              Force base OS mode. The rootfs goes through systemd
                        detection and package installation (apt/dnf). Use this
                        for OS images that the heuristic misclassifies.

      app               Force application mode. Requires --base-fs to specify
                        a systemd-capable rootfs as the base layer. The OCI
                        rootfs is placed under /oci/apps/{name}/root and a
                        systemd unit is generated to run the application.

    The default_base_fs config key provides a default --base-fs value for OCI
    app imports when the flag is not specified on the command line.

PACKAGE INSTALLATION (--install-packages):
    When a rootfs lacks systemd or dbus, --install-packages runs distro-specific
    commands via chroot to make it bootable under systemd-nspawn. The default
    packages are systemd, dbus, and login/pam utilities; the exact commands
    vary per distro family. To view the effective commands:

      sdme config get

    To override the default commands for a distro family:

      sdme config set distros.debian.import_prehook '[\"cmd1\",\"cmd2\"]'

    To reset back to the defaults, set to an empty string:

      sdme config set distros.debian.import_prehook ''

    NixOS rootfs are supported but expected to already include systemd and
    dbus. For unrecognized distros, the rootfs must already be bootable,
    otherwise it cannot be imported.

TESTED DISTROS:
    docker.io/ubuntu
    docker.io/debian:bookworm
    docker.io/fedora:41
    docker.io/archlinux:latest
    docker.io/opensuse/tumbleweed:latest

EXAMPLES:
    # Import from Docker Hub
    sdme fs import ubuntu docker.io/ubuntu -v --install-packages=yes

    # Import an OCI app image with a base filesystem
    sdme fs import nginx docker.io/nginx --base-fs=ubuntu -v

    # Import from a local directory (e.g. debootstrap output)
    sdme fs import debian /tmp/debian-root

    # Import from URL
    sdme fs import arch https://example.com/archlinux-rootfs.tar.zst

    # Force re-fetch from registry (skip manifest cache)
    sdme fs import ubuntu docker.io/ubuntu --no-cache -v

    # Import through an HTTP proxy
    sudo -E sdme fs import ubuntu docker.io/ubuntu -v

    # Override distro import prehook via config
    sdme config set distros.debian.import_prehook '[\"apt-get update\",\"apt-get install -y systemd dbus\"]'";

const FS_BUILD_HELP: &str = "\
BUILD CONFIG FORMAT:
    The build config is a line-oriented text file with three directives:

        FROM <rootfs>       Base rootfs (must be first, required, only once).
                            Use 'FROM fs:<name>' for explicit rootfs prefix.
        RUN <command>       Run a shell command inside the container.
        COPY <src> <dst>    Copy a file or directory into the rootfs.

    Lines starting with # and blank lines are ignored.
    A trailing backslash (\\) continues a directive on the next line.
    Leading whitespace on continuation lines is trimmed.
    RUN commands execute via /bin/sh -c and support pipes, &&, etc.
    COPY writes through the merged overlayfs mount while the container
    stays running, so copied files are immediately visible inside.

    COPY does not support these destinations: /run, /dev/shm. systemd
    mounts tmpfs over them at boot, which hides files written to the
    overlayfs upper layer. /tmp is allowed because the build container
    bind-mounts upper/tmp over nspawn's default tmpfs. Overlayfs opaque
    directories are also rejected as destinations.

COPY SOURCE PREFIXES:
    <host-path>             Copy from the host filesystem (default)
    fs:<name>:<path>        Copy from an imported rootfs
    <container>:<path>      Copy from another container

RESUMABLE BUILDS:
    If a build fails at a RUN step, the container's upper layer is preserved.
    Re-running with the same config file resumes from where it left off.
    Config file changes or --no-cache discard the stale state and start fresh.
    COPY source file changes are not tracked for cache invalidation.

EXAMPLE:
    # Import a base rootfs
    sudo debootstrap --include=dbus,systemd noble /tmp/ubuntu
    sudo sdme fs import ubuntu /tmp/ubuntu

    # Create a build config
    cat << EOF > examplefs.sdme
    FROM ubuntu
    RUN apt-get update && \\
        apt-get install -y \\
        systemd-container \\
        curl
    COPY ./target/release/sdme /usr/local/bin/sdme
    EOF

    # Build and use
    sudo sdme fs build examplefs examplefs.sdme
    sudo sdme new -r examplefs";

const FS_EXPORT_HELP: &str = "\
OUTPUT FORMATS (auto-detected from extension or overridden with --fmt):
    dir         Directory copy
    tar         Uncompressed tarball
    tar.gz      Gzip-compressed tarball
    tar.bz2     Bzip2-compressed tarball
    tar.xz      XZ-compressed tarball
    tar.zst     Zstd-compressed tarball
    raw         Bare filesystem disk image (ext4 or btrfs)
    raw --vm    GPT-partitioned disk image for VM boot

CONTAINER VS ROOTFS EXPORT:
    sdme fs export mybox out.tar.gz         Export a container
    sdme fs export fs:ubuntu out.tar.gz     Export from the rootfs catalogue

    Running containers are read from their merged overlayfs view (with a
    consistency warning). Stopped containers use a temporary read-only
    overlay mount.

VM EXPORT:
    sdme fs export mybox disk.raw --vm --root-password '' --ssh-key ~/.ssh/id_ed25519.pub

    Creates a GPT-partitioned image with serial console, fstab, and DHCP
    networking. Boot with:

      cloud-hypervisor --kernel vmlinuz --disk path=disk.raw --console tty --serial off
      qemu-system-x86_64 -drive file=disk.raw,format=raw -nographic

    Optional flags: --dns (copy host resolv.conf or specify IPs), --swap 512M,
    --hostname myvm, --install-packages yes, --timezone UTC,
    --net-ifaces 2 (number of DHCP interfaces).

PACKAGE INSTALLATION (--install-packages, --vm only):
    When building a VM image, --install-packages runs distro-specific commands
    via chroot to install packages needed for VM boot (e.g. udev). The exact
    commands vary per distro family. To view the effective commands:

      sdme config get

    To override the default commands for a distro family:

      sdme config set distros.debian.export_vm_prehook '[\"cmd1\",\"cmd2\"]'

    To reset back to the defaults, set to an empty string:

      sdme config set distros.debian.export_vm_prehook ''

    Non-VM exports use export_prehook instead (e.g. to restore file
    capabilities stripped during import).

CONFIG KEYS:
    default_export_fs           Filesystem type for raw images (default: ext4)
    default_export_free_space   Extra free space in auto-sized images (default: 256M)

EXAMPLES:
    sdme fs export mybox /tmp/backup.tar.zst
    sdme fs export fs:ubuntu /tmp/ubuntu.tar.gz
    sdme fs export mybox disk.raw --fmt raw --size 4G
    sdme fs export mybox disk.raw --vm --timezone America/New_York";

const FS_CACHE_HELP: &str = "\
The OCI blob cache stores downloaded container image layer blobs and resolved
manifests. Layers are content-addressed by SHA-256 digest. Manifests are cached
with a configurable TTL to avoid redundant registry requests.

CONFIG KEYS:
    oci_cache_dir              Cache directory (default: {datadir}/cache/oci)
    oci_cache_max_size         Maximum cache size with LRU eviction (default: 10G)
    oci_manifest_cache_ttl     Manifest cache TTL in seconds (default: 900, 0 disables)

The --no-cache flag on 'fs import', 'kube apply', and 'kube create' overrides
the manifest TTL to 0 for a single invocation, forcing a fresh registry fetch.

EXAMPLES:
    sdme fs cache info
    sdme fs cache ls
    sdme fs cache clean
    sdme fs cache clean --all";

const CONFIG_HELP: &str = "\
CONFIG KEYS:
    interactive                    bool     yes       Prompt on destructive ops
    datadir                        path     /var/lib/sdme
    boot_timeout                   u64      60        Seconds to wait for boot
    join_as_sudo_user              bool     yes       Drop to sudo user on join
    host_rootfs_opaque_dirs        string   /etc/systemd/system,/var/log
    hardened_drop_caps             string   CAP_SYS_PTRACE,CAP_NET_RAW,CAP_SYS_RAWIO,CAP_SYS_BOOT
    default_base_fs                string   (empty)   Default --base-fs for OCI app imports
    default_output_format          string   (empty)   Default output for ps/fs ls (json, json-pretty)
    default_kube_registry          string   docker.io Registry for unqualified kube image names
    default_export_fs              string   ext4      Filesystem for raw image export
    default_export_free_space      string   256M      Extra free space in auto-sized images
    tasks_max                      u32      16384     Max tasks per container
    oci_cache_dir                  string   (empty)   OCI cache dir ({datadir}/cache/oci)
    oci_cache_max_size             string   10G       Max OCI cache size (0 disables)
    oci_manifest_cache_ttl         u64      900       Manifest cache TTL in seconds (0 disables)
    http_timeout                   u64      30        HTTP connect/resolve timeout (seconds)
    http_body_timeout              u64      300       HTTP body receive timeout (seconds)
    max_download_size              string   50G       Max download size (0 = unlimited)
    stop_timeout_graceful          u64      90        Graceful stop timeout (seconds)
    stop_timeout_terminate         u64      30        Terminate stop timeout (seconds)
    stop_timeout_kill              u64      15        Force-kill stop timeout (seconds)
    auto_fs_gc                     bool     yes       Auto-clean stale transactions
    default_create_masked_services string   systemd-resolved.service
    docker_user                    string   (empty)   Docker Hub username
    docker_token                   string   (empty)   Docker Hub access token

DISTRO PREHOOKS:
    Per-distro chroot commands for import/export preparation. Absent = built-in
    defaults. Empty array = do nothing.

    sdme config set distros.debian.import_prehook '[\"cmd1\",\"cmd2\"]'
    sdme config set distros.debian.import_prehook ''

    Available families: debian, fedora, arch, suse, nixos, unknown.
    Hooks: import_prehook, export_prehook, export_vm_prehook.

EXAMPLES:
    sdme config get
    sdme config set boot_timeout 120
    sdme config set default_base_fs ubuntu
    sdme config set oci_manifest_cache_ttl 0";

const APPARMOR_PROFILE_HELP: &str = "\
INSTALLATION:
    Save the profile and load it into AppArmor:

        sdme config apparmor-profile > /etc/apparmor.d/sdme-default
        apparmor_parser -r /etc/apparmor.d/sdme-default

    To verify the profile is loaded:

        aa-status | grep sdme-default

    The profile is automatically applied when using --strict, or can
    be applied manually with --apparmor-profile sdme-default.

    The deb and rpm packages install and load the profile automatically.

APPARMOR DOCUMENTATION:
    https://gitlab.com/apparmor/apparmor/-/wikis/Documentation";

const POD_HELP: &str = "\
A pod is a shared network namespace (loopback only) that multiple containers
can join, allowing them to communicate via localhost. Similar in concept to a
Kubernetes pod.

Two ways to join a pod:

  --pod <name>       The entire nspawn container runs in the pod's network
                     namespace. Works with --userns and --hardened; the
                     netns is entered via nsenter before nspawn creates the
                     user namespace.

  --oci-pod <name>   Only the OCI app process enters the pod's network
                     namespace (via a systemd NetworkNamespacePath= drop-in).
                     Requires --private-network (or --hardened/--strict).
                     Works with user namespace isolation.

Both flags can be combined on the same container.

EXTERNAL NETWORKING:
    Pods start with loopback-only networking. Use 'pod net attach' to give
    containers in a pod external connectivity via a veth pair. The host's
    systemd-networkd handles DHCP, NAT, and IP forwarding automatically.

    Two modes:

      veth             Point-to-point veth between pod and host.
      zone <name>      Connect to a named zone bridge for inter-pod and
                       inter-container networking (same as --network-zone).

    Attach and detach are live: running containers immediately see the
    interface appear or disappear. Works with both --pod and --oci-pod.

    DNS: attach extracts DNS servers from the DHCP lease and writes
    /etc/resolv.conf into all running pod containers. New containers
    joining the pod get DNS at start time. Detach removes the generated
    resolv.conf from running containers.

    Requires: iproute2 (ip), dhcpcd.

EXAMPLES:
    # Create a pod and add containers
    sdme pod new mypod
    sdme new app1 -r nginx --pod mypod
    sdme new app2 -r redis --pod mypod

    # Create pod with immediate external networking
    sdme pod new mypod --attach veth
    sdme pod new mypod --attach zone --zone myzone

    # OCI pod with hardened security
    sdme pod new mypod
    sdme new app -r nginx --oci-pod mypod --hardened

    # Attach external networking (veth)
    sdme pod net attach mypod veth

    # Attach external networking (zone)
    sdme pod net attach mypod zone myzone

    # Detach external networking
    sdme pod net detach mypod

    # List pods (table, JSON, or pretty JSON)
    sdme pod ls
    sdme pod ls --json
    sdme pod ls --json-pretty

    # Remove a pod
    sdme pod rm mypod";

const KUBE_HELP: &str = "\
Run Kubernetes Pod YAML as a local systemd-nspawn container. Accepts kind: Pod
(v1) and kind: Deployment (apps/v1, extracts the pod template). Multi-container
pods run as a single nspawn container with one systemd service per app.

WORKFLOW:
    # Import a base filesystem
    sdme fs import ubuntu docker.io/ubuntu -v --install-packages=yes

    # Apply a Pod YAML
    sdme kube apply -f pod.yaml --base-fs ubuntu

    # Interact with the container
    sdme join <podname> --oci
    sdme exec <podname> --oci -- curl localhost:8080
    sdme logs <podname> --oci

    # Clean up
    sdme kube delete <podname>

MINIMAL POD YAML:
    apiVersion: v1
    kind: Pod
    metadata:
      name: myapp
    spec:
      containers:
        - name: web
          image: nginx

IMAGE RESOLUTION:
    Short image names (nginx, redis) are resolved using the default_kube_registry
    config key (default: docker.io). Fully qualified names (quay.io/nginx/...)
    are used as-is. Change the default with:
        sdme config set default_kube_registry registry.example.com

NETWORKING:
    Network flags (--network-veth, --network-zone, --network-bridge, --port)
    are available and merged with ports declared in the Pod YAML. The Pod
    spec hostNetwork field is supported: hostNetwork: true keeps the
    container on the host network. Port forwarding works for external
    traffic; from the host use the container IP ('sdme ps').

SUPPORTED FEATURES:
    - Multi-container pods (shared network namespace via localhost)
    - command/args (overrides Docker ENTRYPOINT/CMD)
    - env, envFrom (valueFrom: secretKeyRef, configMapKeyRef)
    - Volumes: emptyDir, hostPath, secret, configMap, persistentVolumeClaim
    - Volume mounts with readOnly and subPath
    - Probes: startup, liveness, readiness (exec, httpGet, tcpSocket, grpc)
    - Restart policy: Always, OnFailure, Never
    - Networking: hostNetwork, --network-veth, --network-zone, --network-bridge, --port
    - Security: --strict, --hardened, --userns (nspawn-level)
    - Secrets and configmaps: sdme kube secret create, sdme kube configmap create

SECURITY:
    CLI flags (--strict, --hardened, etc.) apply at the nspawn container level.
    Pod YAML securityContext applies at the OCI app service level. Both layers
    are complementary and can be used together.";

const PRUNE_HELP: &str = "\
Remove unused filesystems, unhealthy containers, orphaned pods, stale
transactions, and unreferenced secrets, configmaps, and volumes.

Runs an analysis phase first, displays what would be pruned, and asks
for confirmation before proceeding. The configured default_base_fs is
never pruned.

EXAMPLES:
    # Interactive: analyze, show summary, confirm
    sdme prune

    # Dry run: show what would be pruned without removing anything
    sdme prune --dry-run

    # Skip confirmation prompt
    sdme prune --force

    # Exclude specific items from pruning
    sdme prune --except=ubuntu,db-creds

    # Exclude by category when names collide
    sdme prune --except=secret:myapp,container:myapp

CATEGORIES:
    Filesystems          Imported rootfs with no containers using them
    Containers           Containers with non-ok health status
    Pods                 Pod network namespaces with no containers attached
    Secrets              Kube secrets (copied at create time, not runtime-bound)
    ConfigMaps           Kube configmaps (copied at create time, not runtime-bound)
    Volumes              Orphaned volume directories (no matching container)
    Stale transactions   Leftover staging dirs from interrupted operations

NOTES:
    Secrets and configmaps are included because they are copied into the
    kube rootfs at create time and are not referenced at runtime. If you
    plan to reuse them in future kube apply commands, exclude them with
    --except.

    The --except flag accepts plain names (matches all categories) or
    category:name prefixes to disambiguate when a name appears in
    multiple categories. Prefixes: fs, container, pod, secret, configmap,
    volume, txn.

    The OCI blob cache is not pruned. It has its own size-based eviction
    (oci_cache_max_size) and can be cleaned with 'sdme fs cache clean'.";

const UPGRADE_HELP: &str = "\
Replace the running sdme binary with the latest release after verifying
its SHA-256 checksum.

Downloads the release artifact for the current architecture, verifies it
against SHA256SUMS from the same release, and atomically renames it over
the running binary. Safe to run while sdme is executing: the kernel keeps
the old inode mapped until the process exits.

The check and download use the URLs configured under [update_check] in
sdme.conf. By default these point at github.com/fiorix/sdme; mirror
operators can override them to serve the same artifacts internally.

EXAMPLES:
    # Check what's available without downloading
    sdme upgrade --check

    # Upgrade to the latest release (interactive confirmation)
    sudo sdme upgrade

    # Upgrade non-interactively (CI, Ansible, etc.)
    sudo sdme upgrade -y

    # Pin to a specific version (also allows downgrading)
    sudo sdme upgrade --version 0.6.10 -y

NOTES:
    The current user must be root and the directory containing the sdme
    binary must be writable. HTTP responses are bounded and the download
    is rejected if it exceeds 128 MiB.

    Progress and success lines say \"upgrading\"/\"upgraded\" when the
    target is newer than the running binary, and
    \"downgrading\"/\"downgraded\" when it is older (with --version).

    Signatures (GPG/minisign) are not verified; trust is anchored in
    HTTPS plus the SHA-256 in the release-hosted SHA256SUMS file, the
    same model as install.sh.";

// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "sdme",
    version,
    about = "The systemd machine editor",
    long_about = "The systemd machine editor\n\nhttps://github.com/fiorix/sdme",
    after_long_help = CLI_HELP
)]
struct Cli {
    /// Enable verbose output (implies non-interactive mode at runtime)
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Path to config file (default: /etc/sdme.conf)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage configuration
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Create a new container
    #[command(after_long_help = CREATE_HELP)]
    Create {
        /// Container name (generated if not provided)
        name: Option<String>,

        /// Root filesystem to use (host filesystem if not provided)
        #[arg(short = 'r', long = "fs")]
        fs: Option<String>,

        /// Memory limit (e.g. 512M, 2G)
        #[arg(long)]
        memory: Option<String>,

        /// CPU limit as number of CPUs (e.g. 2, 0.5)
        #[arg(long)]
        cpus: Option<String>,

        /// CPU weight 1-10000 (default: 100)
        #[arg(long)]
        cpu_weight: Option<String>,

        /// Make directories opaque in overlayfs (hides lower layer contents, comma-separated or repeatable)
        #[arg(short = 'o', long = "overlayfs-opaque-dirs", value_delimiter = ',')]
        opaque_dirs: Vec<String>,

        /// Join a pod network namespace (entire container runs in the pod's netns)
        #[arg(long)]
        pod: Option<String>,

        /// Join a pod network namespace for the OCI app process only (requires OCI app rootfs)
        #[arg(long)]
        oci_pod: Option<String>,

        #[command(flatten)]
        network: NetworkArgs,

        #[command(flatten)]
        mounts: MountArgs,

        #[command(flatten)]
        security: SecurityArgs,

        /// Do not auto-forward ports declared in the OCI image
        #[arg(long)]
        no_oci_ports: bool,

        /// Do not auto-mount volumes declared in the OCI image
        #[arg(long)]
        no_oci_volumes: bool,

        /// Set environment variable for the OCI app service (KEY=VALUE, repeatable)
        #[arg(long, value_name = "KEY=VALUE")]
        oci_env: Vec<String>,

        /// Enable auto-start on boot
        #[arg(long)]
        enable: bool,

        /// Systemd services to mask in the overlayfs upper layer (comma-separated, overrides config default)
        #[arg(long, value_delimiter = ',')]
        masked_services: Option<Vec<String>>,

        /// Start the container after creating it (remove on start failure)
        #[arg(long)]
        started: bool,

        /// Boot timeout in seconds (overrides config, default: 60; requires --started)
        #[arg(short, long, requires = "started")]
        timeout: Option<u64>,
    },

    /// Copy files between host, containers, and root filesystems
    #[command(after_long_help = CP_HELP)]
    Cp {
        /// Source path (host path, NAME:/path, or fs:NAME:/path)
        source: String,
        /// Destination path (host path, NAME:/path, or fs:NAME:/path)
        destination: String,
        /// Allow device nodes and skip safety prompts
        #[arg(short, long)]
        force: bool,
    },

    /// Show filesystem changes in a container
    #[command(after_long_help = DIFF_HELP)]
    Diff {
        /// Target: container name or FROM..TO (range)
        target: String,

        /// Show summary statistics only
        #[arg(long)]
        stat: bool,

        /// Show only file paths (no status prefix)
        #[arg(long, conflicts_with = "stat")]
        name_only: bool,

        /// Paths to filter (only show changes under these paths)
        #[arg(last = true)]
        paths: Vec<String>,
    },

    /// Run a command in a running container
    #[command(after_long_help = EXEC_HELP)]
    Exec {
        /// Container name
        name: String,
        /// Enter the OCI app's namespaces (optional app name for multi-container kube pods)
        #[arg(long, num_args = 0..=1, default_missing_value = "", value_name = "APP")]
        oci: Option<String>,
        /// Command to run inside the container
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },

    /// Enter a running container
    #[command(after_long_help = JOIN_HELP)]
    Join {
        /// Container name
        name: String,

        /// Start the container if it is stopped
        #[arg(long)]
        start: bool,

        /// Boot timeout in seconds (overrides config, default: 60)
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Enter the OCI app's namespaces (optional app name for multi-container kube pods; default shell: /bin/sh)
        #[arg(long, num_args = 0..=1, default_missing_value = "", value_name = "APP")]
        oci: Option<String>,

        /// Command to run inside the container (default: login shell)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Show container logs (journalctl)
    #[command(after_long_help = LOGS_HELP)]
    Logs {
        /// Container name
        name: String,
        /// Show OCI app service logs (optional app name for multi-container kube pods)
        #[arg(long, num_args = 0..=1, default_missing_value = "", value_name = "APP")]
        oci: Option<String>,
        /// Extra arguments passed to journalctl (e.g. -f, -n 100)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Create, start, and enter a new container
    #[command(after_long_help = NEW_HELP)]
    New {
        /// Container name (generated if not provided)
        name: Option<String>,

        /// Root filesystem to use (host filesystem if not provided)
        #[arg(short = 'r', long = "fs")]
        fs: Option<String>,

        /// Boot timeout in seconds (overrides config, default: 60)
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Memory limit (e.g. 512M, 2G)
        #[arg(long)]
        memory: Option<String>,

        /// CPU limit as number of CPUs (e.g. 2, 0.5)
        #[arg(long)]
        cpus: Option<String>,

        /// CPU weight 1-10000 (default: 100)
        #[arg(long)]
        cpu_weight: Option<String>,

        /// Make directories opaque in overlayfs (hides lower layer contents, comma-separated or repeatable)
        #[arg(short = 'o', long = "overlayfs-opaque-dirs", value_delimiter = ',')]
        opaque_dirs: Vec<String>,

        /// Join a pod network namespace (entire container runs in the pod's netns)
        #[arg(long)]
        pod: Option<String>,

        /// Join a pod network namespace for the OCI app process only (requires OCI app rootfs)
        #[arg(long)]
        oci_pod: Option<String>,

        #[command(flatten)]
        network: NetworkArgs,

        #[command(flatten)]
        mounts: MountArgs,

        #[command(flatten)]
        security: SecurityArgs,

        /// Do not auto-forward ports declared in the OCI image
        #[arg(long)]
        no_oci_ports: bool,

        /// Do not auto-mount volumes declared in the OCI image
        #[arg(long)]
        no_oci_volumes: bool,

        /// Set environment variable for the OCI app service (KEY=VALUE, repeatable)
        #[arg(long, value_name = "KEY=VALUE")]
        oci_env: Vec<String>,

        /// Enable auto-start on boot
        #[arg(long)]
        enable: bool,

        /// Systemd services to mask in the overlayfs upper layer (comma-separated, overrides config default)
        #[arg(long, value_delimiter = ',')]
        masked_services: Option<Vec<String>>,

        /// Command to run inside the container (default: login shell)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// List containers
    #[command(after_long_help = PS_HELP)]
    Ps {
        /// Output as compact JSON
        #[arg(long)]
        json: bool,

        /// Output as pretty-printed JSON
        #[arg(long, conflicts_with = "json")]
        json_pretty: bool,
    },

    /// Remove one or more containers
    Rm {
        /// Container names
        #[arg(required_unless_present = "all")]
        names: Vec<String>,

        /// Remove all containers
        #[arg(short, long, conflicts_with = "names")]
        all: bool,

        /// Skip confirmation prompts
        #[arg(short, long)]
        force: bool,
    },

    /// Stop one or more running containers
    #[command(after_long_help = STOP_HELP)]
    Stop {
        /// Container names
        #[arg(required_unless_present = "all")]
        names: Vec<String>,

        /// Stop all running containers
        #[arg(short, long, conflicts_with = "names")]
        all: bool,

        /// Terminate (SIGTERM to nspawn leader, 30s timeout)
        #[arg(long, conflicts_with = "kill")]
        term: bool,

        /// Force-kill all processes (SIGKILL, 15s timeout)
        #[arg(long, conflicts_with = "term")]
        kill: bool,
    },

    /// Enable containers to start automatically on boot
    Enable {
        /// Container names
        #[arg(required = true)]
        names: Vec<String>,
    },

    /// Disable containers from starting automatically on boot
    Disable {
        /// Container names
        #[arg(required = true)]
        names: Vec<String>,
    },

    /// Set resource limits on a container (replaces all limits)
    Set {
        /// Container name
        name: String,

        /// Memory limit (e.g. 512M, 2G)
        #[arg(long)]
        memory: Option<String>,

        /// CPU limit as number of CPUs (e.g. 2, 0.5)
        #[arg(long)]
        cpus: Option<String>,

        /// CPU weight 1-10000 (default: 100)
        #[arg(long)]
        cpu_weight: Option<String>,
    },

    /// Start one or more containers
    Start {
        /// Container names
        #[arg(required_unless_present = "all")]
        names: Vec<String>,

        /// Start all stopped containers
        #[arg(short, long, conflicts_with = "names")]
        all: bool,

        /// Boot timeout in seconds (overrides config, default: 60)
        #[arg(short, long)]
        timeout: Option<u64>,
    },

    /// Restart one or more containers (stop then start)
    #[command(after_long_help = RESTART_HELP)]
    Restart {
        /// Container names
        #[arg(required_unless_present = "all")]
        names: Vec<String>,

        /// Restart all running containers
        #[arg(short, long, conflicts_with = "names")]
        all: bool,

        /// Terminate (SIGTERM to nspawn leader, 30s timeout)
        #[arg(long, conflicts_with = "kill")]
        term: bool,

        /// Force-kill all processes (SIGKILL, 15s timeout)
        #[arg(long, conflicts_with = "term")]
        kill: bool,

        /// Boot timeout in seconds (overrides config, default: 60)
        #[arg(short, long)]
        timeout: Option<u64>,
    },

    /// Manage root filesystems
    #[command(name = "fs", subcommand)]
    Fs(RootfsCommand),

    /// Manage pod network namespaces
    #[command(name = "pod", subcommand)]
    Pod(PodCommand),

    /// Manage Kubernetes-compatible pods
    #[command(name = "kube", subcommand)]
    Kube(KubeCommand),

    /// Remove unused resources (filesystems, containers, pods, volumes, secrets, configmaps)
    #[command(after_long_help = PRUNE_HELP)]
    Prune {
        /// Show what would be pruned without removing anything
        #[arg(long)]
        dry_run: bool,

        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,

        /// Exclude items by name (comma-separated, supports category:name prefix)
        #[arg(long, value_delimiter = ',')]
        except: Vec<String>,
    },

    /// Download and install the latest sdme release
    #[command(after_long_help = UPGRADE_HELP)]
    Upgrade {
        /// Only check and report; do not download or replace the binary
        #[arg(long)]
        check: bool,

        /// Assume yes; do not prompt for confirmation
        #[arg(short = 'y', long)]
        yes: bool,

        /// Pin to a specific version (e.g. 0.7.0) instead of latest
        #[arg(long, value_name = "VERSION")]
        version: Option<String>,
    },
}

#[derive(Subcommand)]
#[command(after_long_help = FS_HELP)]
#[allow(clippy::large_enum_variant)]
enum RootfsCommand {
    /// Import a root filesystem from a directory, tarball, URL, OCI image, registry image, or QCOW2 disk image
    #[command(after_long_help = FS_IMPORT_HELP)]
    Import {
        /// Name for the imported rootfs
        name: String,
        /// Source: directory path, tarball (.tar, .tar.gz, .tar.bz2, .tar.xz, .tar.zst), URL, OCI image (.oci.tar.xz, etc.), registry image (e.g. quay.io/repo:tag), or QCOW2 disk image
        source: String,
        /// Remove leftover staging directory from a previous failed import
        #[arg(short, long)]
        force: bool,
        /// Whether to install systemd packages if missing (auto: prompt if interactive)
        #[arg(long, value_enum, default_value_t = InstallPackages::Auto)]
        install_packages: InstallPackages,
        /// OCI image classification: auto-detect, force base OS, or force application
        #[arg(long, value_enum, default_value_t = OciMode::Auto)]
        oci_mode: OciMode,
        /// Base rootfs for OCI application images (must have systemd; OCI rootfs goes under /oci/apps/{name}/root)
        #[arg(long)]
        base_fs: Option<String>,

        /// Skip the OCI manifest cache and re-fetch from the registry
        #[arg(long)]
        no_cache: bool,
    },
    /// List imported root filesystems
    Ls {
        /// Output as compact JSON
        #[arg(long)]
        json: bool,

        /// Output as pretty-printed JSON
        #[arg(long, conflicts_with = "json")]
        json_pretty: bool,
    },
    /// Remove one or more imported root filesystems
    Rm {
        /// Names of the rootfs entries to remove
        #[arg(required_unless_present = "all")]
        names: Vec<String>,

        /// Remove all imported root filesystems
        #[arg(short, long, conflicts_with = "names")]
        all: bool,

        /// Skip confirmation prompts
        #[arg(short, long)]
        force: bool,
    },
    /// Build a root filesystem from a build config
    #[command(after_long_help = FS_BUILD_HELP)]
    Build {
        /// Name for the new rootfs
        name: String,
        /// Path to the build config file
        #[arg(name = "build.conf")]
        config: PathBuf,
        /// Boot timeout in seconds (overrides config, default: 60)
        #[arg(short, long)]
        timeout: Option<u64>,
        /// Remove existing rootfs with the same name before building
        #[arg(short, long)]
        force: bool,
        /// Do not resume from a previous failed build
        #[arg(long)]
        no_cache: bool,
    },
    /// Export a container or rootfs to a directory, tarball, or disk image
    #[command(after_long_help = FS_EXPORT_HELP)]
    Export {
        /// Container name, or fs:<name> for rootfs catalogue export
        name: String,
        /// Output path (format auto-detected from extension, or use --fmt)
        output: String,
        /// Overwrite output path if it already exists
        #[arg(short = 'f', long)]
        force: bool,
        /// Output format: dir, tar, tar.gz, tar.bz2, tar.xz, tar.zst, raw
        #[arg(long = "fmt")]
        format: Option<String>,
        /// Override disk image size for raw format (e.g. "2G"); ignores --free-space
        #[arg(short, long)]
        size: Option<String>,
        /// Extra free space added to auto-calculated image size (default: config default_export_free_space; ignored when --size is set)
        #[arg(long)]
        free_space: Option<String>,
        /// Filesystem type for raw disk images (ext4 or btrfs; default: config default_export_fs)
        #[arg(long)]
        filesystem: Option<String>,
        /// Prepare raw disk image for VM boot (serial console, fstab, DHCP, etc.)
        #[arg(long)]
        vm: bool,
        /// DNS nameserver(s) for --vm (repeatable; without value copies host resolv.conf)
        #[arg(long = "dns", requires = "vm", num_args = 0..)]
        dns: Option<Vec<String>>,
        /// Number of network interfaces to configure for DHCP (default: 1; 0 to skip)
        #[arg(long, requires = "vm", default_value_t = 1)]
        net_ifaces: u32,
        /// Set root password (empty string for passwordless root)
        #[arg(long, requires = "vm")]
        root_password: Option<String>,
        /// SSH public key or path to .pub file for root authorized_keys
        #[arg(long, requires = "vm")]
        ssh_key: Option<String>,
        /// Create a swap partition of the given size (e.g. "512M", "2G")
        #[arg(long, requires = "vm")]
        swap: Option<String>,
        /// Set VM hostname (default: rootfs/container name)
        #[arg(long, requires = "vm")]
        hostname: Option<String>,
        /// Install missing packages (e.g. udev) into rootfs for VM boot
        #[arg(long, value_enum, default_value_t = InstallPackages::Auto, requires = "vm")]
        install_packages: InstallPackages,
        /// Set timezone in exported rootfs (e.g. America/New_York)
        #[arg(long)]
        timezone: Option<String>,
    },
    /// Manage the OCI blob cache
    #[command(subcommand)]
    Cache(CacheCommand),
    /// Clean up stale transaction artifacts from interrupted operations
    Gc,
}

#[derive(Subcommand)]
#[command(after_long_help = CONFIG_HELP)]
enum ConfigCommand {
    /// Show current configuration
    Get,
    /// Set a configuration value
    Set {
        /// Configuration key
        key: String,
        /// Configuration value
        value: String,
    },
    /// Print the default AppArmor profile for sdme containers
    #[command(name = "apparmor-profile", after_long_help = APPARMOR_PROFILE_HELP)]
    AppArmorProfile,
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand)]
#[command(after_long_help = POD_HELP)]
enum PodCommand {
    /// Create a new pod network namespace
    New {
        /// Pod name
        name: String,
        /// Attach external networking immediately after creation
        #[arg(long, value_enum)]
        attach: Option<pod::NetMode>,
        /// Zone name (required when --attach zone)
        #[arg(long)]
        zone: Option<String>,
    },
    /// List pods
    Ls {
        /// Output as compact JSON
        #[arg(long)]
        json: bool,
        /// Output as pretty-printed JSON
        #[arg(long, conflicts_with = "json")]
        json_pretty: bool,
    },
    /// Remove one or more pods
    Rm {
        /// Pod names
        #[arg(required_unless_present = "all")]
        names: Vec<String>,
        /// Remove all pods
        #[arg(short, long, conflicts_with = "names")]
        all: bool,
        /// Force removal even if containers reference the pod
        #[arg(short, long)]
        force: bool,
    },
    /// Manage pod external networking
    #[command(subcommand)]
    Net(PodNetCommand),
}

#[derive(Subcommand)]
enum PodNetCommand {
    /// Attach external networking to a pod
    Attach {
        /// Pod name
        name: String,
        /// Network mode: veth or zone
        #[arg(value_enum)]
        mode: pod::NetMode,
        /// Zone name (required for zone mode)
        zone: Option<String>,
    },
    /// Detach external networking from a pod
    Detach {
        /// Pod name
        name: String,
    },
}

#[derive(Subcommand)]
#[command(after_long_help = KUBE_HELP)]
enum KubeCommand {
    /// Create and start a kube pod from a YAML file, then enter the container
    Apply {
        /// Path to Kubernetes Pod or Deployment YAML file
        #[arg(short, long)]
        file: String,

        /// Base root filesystem for the pod (default: config default_base_fs)
        #[arg(long)]
        base_fs: Option<String>,

        /// Boot timeout in seconds (overrides config, default: 60)
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Join a pod network namespace (entire container runs in the pod's netns)
        #[arg(long)]
        pod: Option<String>,

        /// Join a pod network namespace for all OCI app processes (requires private network)
        #[arg(long)]
        oci_pod: Option<String>,

        #[command(flatten)]
        network: NetworkArgs,

        #[command(flatten)]
        security: SecurityArgs,

        /// Systemd services to mask in the overlayfs upper layer (comma-separated, overrides config default)
        #[arg(long, value_delimiter = ',')]
        masked_services: Option<Vec<String>>,

        /// Skip the OCI manifest cache and re-fetch from the registry
        #[arg(long)]
        no_cache: bool,
    },
    /// Create a kube pod from a YAML file (without starting)
    Create {
        /// Path to Kubernetes Pod or Deployment YAML file
        #[arg(short, long)]
        file: String,

        /// Base root filesystem for the pod (default: config default_base_fs)
        #[arg(long)]
        base_fs: Option<String>,

        /// Join a pod network namespace (entire container runs in the pod's netns)
        #[arg(long)]
        pod: Option<String>,

        /// Join a pod network namespace for all OCI app processes (requires private network)
        #[arg(long)]
        oci_pod: Option<String>,

        #[command(flatten)]
        network: NetworkArgs,

        #[command(flatten)]
        security: SecurityArgs,

        /// Systemd services to mask in the overlayfs upper layer (comma-separated, overrides config default)
        #[arg(long, value_delimiter = ',')]
        masked_services: Option<Vec<String>>,

        /// Skip the OCI manifest cache and re-fetch from the registry
        #[arg(long)]
        no_cache: bool,
    },
    /// Delete a kube pod (stop, remove container and rootfs)
    Delete {
        /// Pod name
        name: String,

        /// Force deletion even if not a kube pod
        #[arg(short, long)]
        force: bool,
    },
    /// Manage secrets for kube pods
    #[command(subcommand)]
    Secret(KubeSecretCommand),
    /// Manage configmaps for kube pods
    #[command(subcommand)]
    Configmap(KubeConfigmapCommand),
}

#[derive(Subcommand)]
enum KubeSecretCommand {
    /// Create a secret from literal values or files
    Create {
        /// Secret name
        name: String,

        /// Set a literal key=value pair (repeatable)
        #[arg(long = "from-literal", value_name = "KEY=VALUE")]
        from_literal: Vec<String>,

        /// Set a key from a file key=path (repeatable)
        #[arg(long = "from-file", value_name = "KEY=PATH")]
        from_file: Vec<String>,
    },
    /// List secrets
    Ls,
    /// Remove one or more secrets
    Rm {
        /// Secret names
        #[arg(required = true)]
        names: Vec<String>,
    },
}

#[derive(Subcommand)]
enum KubeConfigmapCommand {
    /// Create a configmap from literal values or files
    Create {
        /// ConfigMap name
        name: String,

        /// Set a literal key=value pair (repeatable)
        #[arg(long = "from-literal", value_name = "KEY=VALUE")]
        from_literal: Vec<String>,

        /// Set a key from a file key=path (repeatable)
        #[arg(long = "from-file", value_name = "KEY=PATH")]
        from_file: Vec<String>,
    },
    /// List configmaps
    Ls,
    /// Remove one or more configmaps
    Rm {
        /// ConfigMap names
        #[arg(required = true)]
        names: Vec<String>,
    },
}

#[derive(Subcommand)]
#[command(after_long_help = FS_CACHE_HELP)]
enum CacheCommand {
    /// Show cache location, size, and blob count
    Info,
    /// List cached blobs
    Ls,
    /// Clean up the cache
    Clean {
        /// Remove all cached blobs
        #[arg(long)]
        all: bool,
    },
}

fn main() {
    // Background probe dispatcher: handled before clap so it stays hidden
    // from --help and clap_complete. The probe is spawned as a detached
    // subprocess by maybe_spawn_background_check; this is the child entry.
    // The first `--config <path>` argument (if any) is honored.
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.iter().skip(1).any(|a| a == "__update-check") {
        let cfg_path = parse_config_override(&raw_args);
        let cfg = config::load(cfg_path.as_deref()).unwrap_or_default();
        let _ = sdme::update::run_background_check(&cfg);
        return;
    }

    let result = run();
    // Best-effort update banner (TTY-only, config-gated, errors swallowed).
    // Skipped on interrupt so it doesn't appear after "interrupted, exiting".
    if !sdme::INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed) {
        sdme::update::maybe_print_banner_from_env();
    }
    if let Err(e) = result {
        if sdme::INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!("interrupted, exiting");
            std::process::exit(sdme::interrupt_exit_code());
        }
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

/// Extract the effective `--config <PATH>` value from raw args.
///
/// Kept minimal; only used by the hidden `__update-check` dispatcher which
/// runs before clap. Supports `--config PATH` and `--config=PATH`.
fn parse_config_override(args: &[String]) -> Option<PathBuf> {
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if let Some(rest) = a.strip_prefix("--config=") {
            return Some(PathBuf::from(rest));
        }
        if a == "--config" {
            return it.next().map(PathBuf::from);
        }
    }
    None
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Share the effective --config path with the end-of-run banner in main().
    sdme::update::set_config_override(cli.config.clone());

    // Handle commands that don't require root.
    match cli.command {
        Command::Config(ConfigCommand::Completions { shell }) => {
            clap_complete::generate(shell, &mut Cli::command(), "sdme", &mut std::io::stdout());
            return Ok(());
        }
        Command::Config(ConfigCommand::AppArmorProfile) => {
            return security::print_apparmor_profile();
        }
        _ => {}
    }

    if unsafe { libc::geteuid() } != 0 {
        bail!("sdme requires root privileges; run with sudo");
    }

    sdme::install_interrupt_handler();

    let config_path = cli.config.as_deref();

    if cli.verbose {
        let resolved = config::resolve_path(config_path);
        eprintln!("config: {}", resolved.display());
    }

    let cfg = config::load(config_path)?;

    let interactive =
        cfg.interactive && !cli.verbose && unsafe { libc::isatty(libc::STDIN_FILENO) != 0 };

    let blob_cache = oci::cache::BlobCache::from_config(&cfg)?;

    // Skip the background update probe for commands where it adds no value
    // (the upgrade command already resolved the latest version; config
    // commands terminate fast and have no need to phone home).
    let skip_update_probe = matches!(cli.command, Command::Config(_) | Command::Upgrade { .. });

    match cli.command {
        Command::Config(cmd) => match cmd {
            ConfigCommand::Get => {
                cfg.display();
                display_distro_hooks(&cfg);
            }
            ConfigCommand::Set { key, value } => {
                // Validate the value and produce the TOML representation.
                // The key is written surgically without touching other config keys.
                use toml::Value as V;
                let toml_key;
                let toml_val: Option<V>;

                match key.as_str() {
                    "interactive" => {
                        toml_key = key.clone();
                        toml_val = Some(V::Boolean(match value.as_str() {
                            "yes" => true,
                            "no" => false,
                            _ => {
                                bail!("invalid value for interactive: {value} (expected yes or no)")
                            }
                        }));
                    }
                    "datadir" => {
                        let path = PathBuf::from(&value);
                        if !path.is_absolute() {
                            bail!("datadir must be an absolute path: {value}");
                        }
                        toml_key = key.clone();
                        toml_val = Some(V::String(value));
                    }
                    "boot_timeout" => {
                        let secs: u64 = value.parse().map_err(|_| {
                            anyhow::anyhow!("boot_timeout must be a positive integer (seconds)")
                        })?;
                        if secs == 0 {
                            bail!("boot_timeout must be greater than 0");
                        }
                        toml_key = key.clone();
                        toml_val = Some(V::Integer(secs as i64));
                    }
                    "join_as_sudo_user" => {
                        toml_key = key.clone();
                        toml_val = Some(V::Boolean(match value.as_str() {
                            "yes" => true,
                            "no" => false,
                            _ => bail!(
                                "invalid value for join_as_sudo_user: {value} (expected yes or no)"
                            ),
                        }));
                    }
                    "host_rootfs_opaque_dirs" => {
                        let normalized = if value.is_empty() {
                            String::new()
                        } else {
                            let dirs = parse_opaque_dirs_config(&value);
                            containers::validate_opaque_dirs(&dirs)?.join(",")
                        };
                        toml_key = key.clone();
                        toml_val = Some(V::String(normalized));
                    }
                    "hardened_drop_caps" => {
                        let normalized = if value.is_empty() {
                            String::new()
                        } else {
                            let caps: Vec<String> = value
                                .split(',')
                                .map(|c| security::normalize_cap(c.trim()))
                                .collect();
                            for cap in &caps {
                                security::validate_capability(cap)?;
                            }
                            caps.join(",")
                        };
                        toml_key = key.clone();
                        toml_val = Some(V::String(normalized));
                    }
                    "default_base_fs" => {
                        if !value.is_empty() {
                            sdme::validate_name(&value)?;
                        }
                        toml_key = key.clone();
                        toml_val = Some(V::String(value));
                    }
                    "default_output_format" => {
                        match value.as_str() {
                            "" | "json" | "json-pretty" => {}
                            other => {
                                bail!(
                                    "invalid default_output_format '{other}': \
                                     expected json, json-pretty, or empty for table"
                                )
                            }
                        }
                        toml_key = key.clone();
                        toml_val = Some(V::String(value));
                    }
                    "default_kube_registry" => {
                        if value.is_empty() {
                            bail!("default_kube_registry cannot be empty");
                        }
                        toml_key = key.clone();
                        toml_val = Some(V::String(value));
                    }
                    "default_export_fs" => {
                        match value.as_str() {
                            "ext4" | "btrfs" => {}
                            other => {
                                bail!("invalid default_export_fs '{other}': expected ext4 or btrfs")
                            }
                        }
                        toml_key = key.clone();
                        toml_val = Some(V::String(value));
                    }
                    "tasks_max" => {
                        let v: u32 = value
                            .parse()
                            .context("tasks_max must be a positive integer")?;
                        if v == 0 {
                            bail!("tasks_max must be greater than 0");
                        }
                        toml_key = key.clone();
                        toml_val = Some(V::Integer(v as i64));
                    }
                    "stop_timeout_graceful" | "stop_timeout_terminate" | "stop_timeout_kill" => {
                        let secs: u64 = value.parse().map_err(|_| {
                            anyhow::anyhow!("{key} must be a positive integer (seconds)")
                        })?;
                        if secs == 0 {
                            bail!("{key} must be greater than 0");
                        }
                        toml_key = key.clone();
                        toml_val = Some(V::Integer(secs as i64));
                    }
                    "docker_user" => {
                        toml_key = key.clone();
                        toml_val = Some(V::String(value));
                    }
                    "docker_token" => {
                        toml_key = key.clone();
                        toml_val = Some(V::String(value));
                    }
                    "oci_cache_dir" => {
                        if !value.is_empty() {
                            let path = PathBuf::from(&value);
                            if !path.is_absolute() {
                                bail!("oci_cache_dir must be an absolute path: {value}");
                            }
                        }
                        toml_key = key.clone();
                        toml_val = Some(V::String(value));
                    }
                    "oci_cache_max_size" => {
                        sdme::parse_size(&value)
                            .with_context(|| format!("invalid oci_cache_max_size: {value}"))?;
                        toml_key = key.clone();
                        toml_val = Some(V::String(value));
                    }
                    "oci_manifest_cache_ttl" => {
                        let v: u64 = value
                            .parse()
                            .context("oci_manifest_cache_ttl must be a number of seconds")?;
                        toml_key = key.clone();
                        toml_val = Some(V::Integer(v as i64));
                    }
                    "http_timeout" => {
                        let v: u64 = value
                            .parse()
                            .context("http_timeout must be a number of seconds")?;
                        toml_key = key.clone();
                        toml_val = Some(V::Integer(v as i64));
                    }
                    "http_body_timeout" => {
                        let v: u64 = value
                            .parse()
                            .context("http_body_timeout must be a number of seconds")?;
                        toml_key = key.clone();
                        toml_val = Some(V::Integer(v as i64));
                    }
                    "max_download_size" => {
                        if value != "0" {
                            sdme::parse_size(&value)
                                .with_context(|| format!("invalid max_download_size: {value}"))?;
                        }
                        toml_key = key.clone();
                        toml_val = Some(V::String(value));
                    }
                    key if key.starts_with("update_check.") => {
                        let subkey = &key["update_check.".len()..];
                        toml_key = key.to_string();
                        toml_val = match subkey {
                            "enabled" => Some(V::Boolean(match value.as_str() {
                                "yes" => true,
                                "no" => false,
                                _ => bail!(
                                    "invalid value for update_check.enabled: {value} (expected yes or no)"
                                ),
                            })),
                            "version_url" | "binary_url_template" | "checksums_url_template" => {
                                if !value.starts_with("https://") {
                                    bail!("update_check.{subkey} must start with https://: {value}");
                                }
                                if subkey == "binary_url_template"
                                    && (!value.contains("{version}") || !value.contains("{arch}"))
                                {
                                    bail!(
                                        "update_check.binary_url_template must contain {{version}} and {{arch}} placeholders"
                                    );
                                }
                                if subkey == "checksums_url_template" && !value.contains("{version}")
                                {
                                    bail!(
                                        "update_check.checksums_url_template must contain {{version}} placeholder"
                                    );
                                }
                                Some(V::String(value))
                            }
                            "check_interval_hours" => {
                                let hours: u64 = value.parse().map_err(|_| {
                                    anyhow::anyhow!(
                                        "update_check.check_interval_hours must be a non-negative integer"
                                    )
                                })?;
                                Some(V::Integer(hours as i64))
                            }
                            other => bail!("unknown config key: update_check.{other}"),
                        };
                    }
                    key if key.starts_with("distros.") => {
                        let parts: Vec<&str> = key.splitn(3, '.').collect();
                        if parts.len() != 3 {
                            bail!(
                                "expected format: distros.<family>.<hook> \
                                 (e.g., distros.debian.import_prehook)"
                            );
                        }
                        let hook = parts[2];
                        if hook != "import_prehook"
                            && hook != "export_prehook"
                            && hook != "export_vm_prehook"
                        {
                            bail!(
                                "unknown hook '{hook}': expected import_prehook, export_prehook, or export_vm_prehook"
                            );
                        }
                        toml_key = key.to_string();
                        toml_val = if value.is_empty() {
                            None // remove the key
                        } else if value.starts_with('[') {
                            let cmds: Vec<String> = serde_json::from_str(&value)
                                .context("expected JSON array of command strings")?;
                            Some(V::Array(cmds.into_iter().map(V::String).collect()))
                        } else {
                            Some(V::Array(vec![V::String(value)]))
                        };
                    }
                    _ => bail!("unknown config key: {key}"),
                }

                if let Some(ref val) = toml_val {
                    if let Some(default_val) = config::default_value_for_key(&toml_key) {
                        if *val == default_val {
                            let msg = if config::key_exists_in_file(config_path, &toml_key)? {
                                config::save_key(config_path, &toml_key, None)?;
                                format!("{toml_key} is the built-in default; removed override from config file")
                            } else {
                                format!("{toml_key} is already the built-in default")
                            };
                            eprintln!("{msg}");
                            return Ok(());
                        }
                    }
                }
                config::save_key(config_path, &toml_key, toml_val)?;
            }
            // Handled before root check above.
            ConfigCommand::AppArmorProfile => unreachable!(),
            ConfigCommand::Completions { .. } => unreachable!(),
        },
        Command::Cp {
            source,
            destination,
            force,
        } => {
            let src = cp::parse_endpoint(&source)?;
            let dst = cp::parse_endpoint(&destination)?;
            cp::cp(
                &cfg.datadir,
                &src,
                &dst,
                &cp::CpOptions {
                    force,
                    verbose: cli.verbose,
                    interactive,
                },
            )?;
        }
        Command::Diff {
            target,
            stat,
            name_only,
            paths,
        } => {
            sdme::diff::diff(
                &cfg.datadir,
                &target,
                &paths,
                &sdme::diff::DiffOptions { stat, name_only },
            )?;
        }
        Command::Create {
            name,
            fs,
            memory,
            cpus,
            cpu_weight,
            opaque_dirs,
            pod,
            oci_pod,
            network,
            mounts,
            security,
            no_oci_ports,
            no_oci_volumes,
            oci_env,
            enable,
            masked_services,
            started,
            timeout,
        } => {
            system_check::check_systemd_version(255)?;
            let limits = parse_limits(memory, cpus, cpu_weight)?;
            let systemd_log_level = security.systemd_log_level.clone();
            if let Some(ref level) = systemd_log_level {
                validate_systemd_log_level(level)?;
            }
            let (mut sec, hardened) = parse_security(security, &cfg)?;
            let mut network = parse_network(network)?;
            if hardened && !network.private_network {
                network.private_network = true;
            }
            retain_net_raw_for_dhcp(&mut sec, &network);
            validate_pod_args(&cfg.datadir, pod.as_deref())?;
            validate_oci_pod_args(
                &cfg.datadir,
                oci_pod.as_deref(),
                fs.as_deref(),
                network.private_network,
            )?;
            let (binds, envs) = parse_mounts(mounts)?;
            let oci_envs = validate_oci_envs(oci_env)?;
            let opaque_dirs = resolve_opaque_dirs(opaque_dirs, fs.is_none(), &cfg);
            let masked_services = resolve_masked_services(masked_services, &network, &cfg)?;

            // Auto-wire OCI ports if the rootfs declares them.
            if !no_oci_ports {
                if let Some(ref rootfs_name) = fs {
                    let rootfs_path = containers::resolve_rootfs(&cfg.datadir, Some(rootfs_name))?;
                    auto_wire_oci_ports(&rootfs_path, &mut network);
                }
            }

            // Read OCI volumes from the rootfs if applicable.
            let oci_volumes =
                read_oci_volumes_for_rootfs(&cfg.datadir, fs.as_deref(), no_oci_volumes)?;

            // Detect OCI app name before moving fs into opts.
            let oci_app_name = fs.as_deref().and_then(|rootfs_name| {
                let rootfs_path = cfg.datadir.join("fs").join(rootfs_name);
                oci::rootfs::detect_oci_app_name(&rootfs_path)
            });

            // Compute lowerdir before fs is moved into opts.
            let lowerdir = match &fs {
                Some(rootfs_name) => cfg
                    .datadir
                    .join("fs")
                    .join(rootfs_name)
                    .to_string_lossy()
                    .to_string(),
                None => "/".to_string(),
            };
            let userns_enabled = sec.userns;

            let opts = containers::CreateOptions {
                name,
                rootfs: fs,
                limits,
                network,
                opaque_dirs,
                pod,
                oci_pod,
                binds,
                envs,
                security: sec,
                oci_volumes,
                oci_envs,
                masked_services,
            };
            let name = containers::create(&cfg.datadir, &opts, cli.verbose)?;

            post_create_setup(
                &cfg.datadir,
                &name,
                &lowerdir,
                oci_app_name.as_deref(),
                systemd_log_level.as_deref(),
                userns_enabled,
                cli.verbose,
            )?;

            eprintln!("creating '{name}'");
            if enable {
                systemd::enable(&systemd::ServiceConfig {
                    datadir: &cfg.datadir,
                    name: &name,
                    tasks_max: cfg.tasks_max,
                    boot_timeout: cfg.boot_timeout,
                    verbose: cli.verbose,
                })?;
                eprintln!("enabled '{name}' for auto-start on boot");
            }
            if started {
                let boot_timeout =
                    std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
                create_and_start(&BootConfig {
                    datadir: &cfg.datadir,
                    name: &name,
                    tasks_max: cfg.tasks_max,
                    boot_timeout,
                    stop_timeout: cfg.stop_timeout_terminate,
                    verbose: cli.verbose,
                })?;
            }
            println!("{name}");
        }
        Command::Exec { name, oci, command } => {
            let name = containers::resolve_name(&cfg.datadir, &name)?;
            let shell_opts = containers::ShellOptions {
                datadir: &cfg.datadir,
                name: &name,
                verbose: cli.verbose,
            };
            let status = if let Some(ref oci_app) = oci {
                let app_name =
                    resolve_oci_app_name(&cfg.datadir, &name, oci_app_explicit(oci_app))?;
                containers::exec_oci(&shell_opts, &app_name, &command)?
            } else {
                containers::exec(&shell_opts, &command, cfg.join_as_sudo_user)?
            };
            std::process::exit(status.code().unwrap_or(1));
        }
        Command::Set {
            name,
            memory,
            cpus,
            cpu_weight,
        } => {
            let name = containers::resolve_name(&cfg.datadir, &name)?;
            let limits = parse_limits(memory, cpus, cpu_weight)?;
            containers::set_limits(&cfg.datadir, &name, &limits, cli.verbose)?;
        }
        Command::Start {
            names,
            all,
            timeout,
        } => {
            system_check::check_systemd_version(255)?;
            let targets: Vec<String> = if all {
                containers::list(&cfg.datadir)?
                    .into_iter()
                    .filter(|e| e.status == "stopped")
                    .map(|e| e.name)
                    .collect()
            } else {
                names
            };
            if targets.is_empty() {
                eprintln!("no stopped containers to start");
                return Ok(());
            }
            let boot_timeout = std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
            let datadir = &cfg.datadir;
            let verbose = cli.verbose;
            for_each_container(datadir, &targets, "starting", "started", |name| {
                containers::ensure_exists(datadir, name)?;
                start_and_await_boot(&BootConfig {
                    datadir,
                    name,
                    tasks_max: cfg.tasks_max,
                    boot_timeout,
                    stop_timeout: cfg.stop_timeout_terminate,
                    verbose,
                })
            })?;
        }
        Command::Enable { names } => {
            let datadir = &cfg.datadir;
            let verbose = cli.verbose;
            for_each_container(datadir, &names, "enabling", "enabled", |name| {
                containers::ensure_exists(datadir, name)?;
                systemd::enable(&systemd::ServiceConfig {
                    datadir,
                    name,
                    tasks_max: cfg.tasks_max,
                    boot_timeout: cfg.boot_timeout,
                    verbose,
                })
            })?;
        }
        Command::Disable { names } => {
            let datadir = &cfg.datadir;
            let verbose = cli.verbose;
            for_each_container(datadir, &names, "disabling", "disabled", |name| {
                containers::ensure_exists(datadir, name)?;
                systemd::disable(datadir, name, verbose)
            })?;
        }
        Command::Join {
            name,
            start,
            timeout,
            oci,
            command,
        } => {
            let name = containers::resolve_name(&cfg.datadir, &name)?;
            containers::ensure_exists(&cfg.datadir, &name)?;

            if !systemd::is_active(&name)? {
                let should_start = if start {
                    true
                } else if interactive {
                    eprintln!("container '{name}' is stopped");
                    sdme::confirm_default_yes("start it? [Y/n] ")?
                } else {
                    bail!("container '{name}' is not running (use --start to start it)");
                };

                if !should_start {
                    bail!("aborted");
                }

                system_check::check_systemd_version(255)?;
                eprintln!("starting '{name}'");
                let boot_timeout =
                    std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
                start_and_await_boot(&BootConfig {
                    datadir: &cfg.datadir,
                    name: &name,
                    tasks_max: cfg.tasks_max,
                    boot_timeout,
                    stop_timeout: cfg.stop_timeout_terminate,
                    verbose: cli.verbose,
                })?;
            }

            if let Some(ref oci_app) = oci {
                let app_name =
                    resolve_oci_app_name(&cfg.datadir, &name, oci_app_explicit(oci_app))?;
                let command = if command.is_empty() {
                    vec!["/bin/sh".to_string()]
                } else {
                    command
                };
                eprintln!("joining '{name}' (oci app '{app_name}')");
                let shell_opts = containers::ShellOptions {
                    datadir: &cfg.datadir,
                    name: &name,
                    verbose: cli.verbose,
                };
                let status = containers::exec_oci(&shell_opts, &app_name, &command)?;
                std::process::exit(status.code().unwrap_or(1));
            }

            eprintln!("joining '{name}'");
            let shell_opts = containers::ShellOptions {
                datadir: &cfg.datadir,
                name: &name,
                verbose: cli.verbose,
            };
            let status = containers::join(&shell_opts, &command, cfg.join_as_sudo_user)?;
            std::process::exit(status.code().unwrap_or(1));
        }
        Command::Logs { name, oci, args } => {
            let name = containers::resolve_name(&cfg.datadir, &name)?;
            if let Some(ref oci_app) = oci {
                let app_name =
                    resolve_oci_app_name(&cfg.datadir, &name, oci_app_explicit(oci_app))?;
                let mut command = vec![
                    "/usr/bin/journalctl".to_string(),
                    "-u".to_string(),
                    format!("sdme-oci-{app_name}.service"),
                ];
                command.extend(args);
                let shell_opts = containers::ShellOptions {
                    datadir: &cfg.datadir,
                    name: &name,
                    verbose: cli.verbose,
                };
                let status = containers::exec(&shell_opts, &command, cfg.join_as_sudo_user)?;
                std::process::exit(status.code().unwrap_or(1));
            } else {
                system_check::check_dependencies(
                    &[("journalctl", "apt install systemd")],
                    cli.verbose,
                )?;
                let unit = systemd::service_name(&name);
                let mut cmd = std::process::Command::new("journalctl");
                cmd.args(["-u", &unit]);
                cmd.args(&args);
                if cli.verbose {
                    eprintln!(
                        "exec: journalctl {}",
                        cmd.get_args()
                            .map(|a| a.to_string_lossy())
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                }
                let err = cmd.exec();
                bail!("failed to exec journalctl: {err}");
            }
        }
        Command::New {
            name,
            fs,
            timeout,
            memory,
            cpus,
            cpu_weight,
            opaque_dirs,
            pod,
            oci_pod,
            network,
            mounts,
            security,
            no_oci_ports,
            no_oci_volumes,
            oci_env,
            enable,
            masked_services,
            command,
        } => {
            system_check::check_systemd_version(255)?;
            let limits = parse_limits(memory, cpus, cpu_weight)?;
            let systemd_log_level = security.systemd_log_level.clone();
            if let Some(ref level) = systemd_log_level {
                validate_systemd_log_level(level)?;
            }
            let (mut sec, hardened) = parse_security(security, &cfg)?;
            let mut network = parse_network(network)?;
            if hardened && !network.private_network {
                network.private_network = true;
            }
            retain_net_raw_for_dhcp(&mut sec, &network);
            validate_pod_args(&cfg.datadir, pod.as_deref())?;
            validate_oci_pod_args(
                &cfg.datadir,
                oci_pod.as_deref(),
                fs.as_deref(),
                network.private_network,
            )?;
            let (binds, envs) = parse_mounts(mounts)?;
            let oci_envs = validate_oci_envs(oci_env)?;
            let opaque_dirs = resolve_opaque_dirs(opaque_dirs, fs.is_none(), &cfg);
            let masked_services = resolve_masked_services(masked_services, &network, &cfg)?;

            // Auto-wire OCI ports if the rootfs declares them.
            if !no_oci_ports {
                if let Some(ref rootfs_name) = fs {
                    let rootfs_path = containers::resolve_rootfs(&cfg.datadir, Some(rootfs_name))?;
                    auto_wire_oci_ports(&rootfs_path, &mut network);
                }
            }

            // Read OCI volumes from the rootfs if applicable.
            let oci_volumes =
                read_oci_volumes_for_rootfs(&cfg.datadir, fs.as_deref(), no_oci_volumes)?;

            // Detect OCI app name before moving fs into opts.
            let oci_app_name = fs.as_deref().and_then(|rootfs_name| {
                let rootfs_path = cfg.datadir.join("fs").join(rootfs_name);
                oci::rootfs::detect_oci_app_name(&rootfs_path)
            });

            // Compute lowerdir before fs is moved into opts.
            let lowerdir = match &fs {
                Some(rootfs_name) => cfg
                    .datadir
                    .join("fs")
                    .join(rootfs_name)
                    .to_string_lossy()
                    .to_string(),
                None => "/".to_string(),
            };
            let userns_enabled = sec.userns;

            let opts = containers::CreateOptions {
                name,
                rootfs: fs,
                limits,
                network,
                opaque_dirs,
                pod,
                oci_pod,
                binds,
                envs,
                security: sec,
                oci_volumes,
                oci_envs,
                masked_services,
            };
            let is_host_rootfs = opts.rootfs.is_none();
            let name = containers::create(&cfg.datadir, &opts, cli.verbose)?;

            post_create_setup(
                &cfg.datadir,
                &name,
                &lowerdir,
                oci_app_name.as_deref(),
                systemd_log_level.as_deref(),
                userns_enabled,
                cli.verbose,
            )?;

            eprintln!("creating '{name}'");

            if enable {
                systemd::enable(&systemd::ServiceConfig {
                    datadir: &cfg.datadir,
                    name: &name,
                    tasks_max: cfg.tasks_max,
                    boot_timeout: cfg.boot_timeout,
                    verbose: cli.verbose,
                })?;
                eprintln!("enabled '{name}' for auto-start on boot");
            }

            // Warn about hardened/strict implications for interactive use.
            if hardened && is_host_rootfs {
                eprintln!("note: --private-network is active; the container has no internet");
                eprintln!("note: --no-new-privileges is active; sudo/su will not work inside");
            }

            let boot_timeout = std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
            create_and_start(&BootConfig {
                datadir: &cfg.datadir,
                name: &name,
                tasks_max: cfg.tasks_max,
                boot_timeout,
                stop_timeout: cfg.stop_timeout_terminate,
                verbose: cli.verbose,
            })?;

            eprintln!("joining '{name}'");
            let shell_opts = containers::ShellOptions {
                datadir: &cfg.datadir,
                name: &name,
                verbose: cli.verbose,
            };
            let status = containers::join(&shell_opts, &command, cfg.join_as_sudo_user)?;
            if !status.success() {
                let code = status.code().unwrap_or(1);
                eprintln!("join failed (exit code {code}), removing '{name}'");
                let _ = containers::remove(&cfg.datadir, &name, cli.verbose);
                std::process::exit(code);
            }
        }
        Command::Ps { json, json_pretty } => {
            let json = json || (!json_pretty && cfg.default_output_format == "json");
            let json_pretty = json_pretty || (!json && cfg.default_output_format == "json-pretty");
            let entries = containers::list(&cfg.datadir)?;
            if json || json_pretty {
                let output = if json_pretty {
                    serde_json::to_string_pretty(&entries)?
                } else {
                    serde_json::to_string(&entries)?
                };
                println!("{output}");
            } else if entries.is_empty() {
                println!("no containers found");
            } else {
                let name_w = entries.iter().map(|e| e.name.len()).max().unwrap().max(4);
                let status_w = entries.iter().map(|e| e.status.len()).max().unwrap().max(6);
                let health_w = entries.iter().map(|e| e.health.len()).max().unwrap().max(6);
                let addr_display: Vec<String> = entries
                    .iter()
                    .map(|e| {
                        let s = e.addresses_display();
                        if s.is_empty() {
                            "-".to_string()
                        } else {
                            s
                        }
                    })
                    .collect();
                let addr_w = addr_display.iter().map(|a| a.len()).max().unwrap().max(9);
                // Header.
                println!(
                    "{:<name_w$}  {:<status_w$}  {:<health_w$}  {:<6}  {:<7}  {:<6}  {:<addr_w$}  OS",
                    "NAME", "STATUS", "HEALTH", "USERNS", "ENABLED", "MOUNTS", "ADDRESSES"
                );
                // Rows.
                for (i, e) in entries.iter().enumerate() {
                    let has_mounts = !e.binds.is_empty()
                        || e.oci_apps.iter().any(|app| !app.volumes.is_empty())
                        || !e.submounts.is_empty();
                    println!(
                        "{:<name_w$}  {:<status_w$}  {:<health_w$}  {:<6}  {:<7}  {:<6}  {:<addr_w$}  {}",
                        e.name,
                        e.status,
                        e.health,
                        if e.userns { "yes" } else { "no" },
                        if e.enabled { "yes" } else { "no" },
                        if has_mounts { "yes" } else { "no" },
                        addr_display[i],
                        e.os,
                    );
                }
            }
        }
        Command::Rm { names, all, force } => {
            let targets: Vec<String> = if all {
                let all_names: Vec<String> = containers::list(&cfg.datadir)?
                    .into_iter()
                    .map(|e| e.name)
                    .collect();
                if all_names.is_empty() {
                    eprintln!("no containers to remove");
                    return Ok(());
                }
                if !force {
                    if !interactive {
                        bail!("use -f to confirm removal in non-interactive mode");
                    }
                    eprintln!(
                        "this will remove {} container{}: {}",
                        all_names.len(),
                        if all_names.len() == 1 { "" } else { "s" },
                        all_names.join(", "),
                    );
                    if !confirm("are you sure? [y/N] ")? {
                        bail!("aborted");
                    }
                }
                all_names
            } else {
                names
            };
            let datadir = &cfg.datadir;
            let verbose = cli.verbose;
            for_each_container(datadir, &targets, "removing", "removed", |name| {
                containers::remove(datadir, name, verbose)
            })?;
        }
        Command::Stop {
            names,
            all,
            term,
            kill,
        } => {
            let (mode, timeout_secs) = if kill {
                (containers::StopMode::Kill, cfg.stop_timeout_kill)
            } else if term {
                (containers::StopMode::Terminate, cfg.stop_timeout_terminate)
            } else {
                (containers::StopMode::Graceful, cfg.stop_timeout_graceful)
            };
            let targets: Vec<String> = if all {
                containers::list(&cfg.datadir)?
                    .into_iter()
                    .filter(|e| e.status != "stopped")
                    .map(|e| e.name)
                    .collect()
            } else {
                names
            };
            if targets.is_empty() {
                eprintln!("no running containers to stop");
                return Ok(());
            }
            let datadir = &cfg.datadir;
            let verbose = cli.verbose;
            for_each_container(datadir, &targets, "stopping", "stopped", |name| {
                containers::ensure_exists(datadir, name)?;
                containers::stop(name, mode, timeout_secs, verbose)
            })?;
        }
        Command::Restart {
            names,
            all,
            term,
            kill,
            timeout,
        } => {
            system_check::check_systemd_version(255)?;
            let (mode, stop_timeout_secs) = if kill {
                (containers::StopMode::Kill, cfg.stop_timeout_kill)
            } else if term {
                (containers::StopMode::Terminate, cfg.stop_timeout_terminate)
            } else {
                (containers::StopMode::Graceful, cfg.stop_timeout_graceful)
            };
            let targets: Vec<String> = if all {
                containers::list(&cfg.datadir)?
                    .into_iter()
                    .filter(|e| e.status != "stopped")
                    .map(|e| e.name)
                    .collect()
            } else {
                names
            };
            if targets.is_empty() {
                eprintln!("no running containers to restart");
                return Ok(());
            }
            let boot_timeout = std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
            let datadir = &cfg.datadir;
            let verbose = cli.verbose;
            let mut failed = false;
            for input in &targets {
                check_interrupted()?;
                let name = match containers::resolve_name(datadir, input) {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("error: {input}: {e}");
                        failed = true;
                        continue;
                    }
                };
                containers::ensure_exists(datadir, &name)?;
                eprintln!("restarting '{name}'");
                if let Err(e) = containers::stop(&name, mode, stop_timeout_secs, verbose) {
                    eprintln!("error: {name}: stop failed: {e}");
                    failed = true;
                    continue;
                }
                if let Err(e) = start_and_await_boot(&BootConfig {
                    datadir,
                    name: &name,
                    tasks_max: cfg.tasks_max,
                    boot_timeout,
                    stop_timeout: cfg.stop_timeout_terminate,
                    verbose,
                }) {
                    eprintln!("error: {name}: start failed: {e}");
                    failed = true;
                } else {
                    println!("{name}");
                }
                if sdme::INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
            }
            check_interrupted()?;
            if failed {
                bail!("some containers could not be restarted");
            }
        }
        Command::Pod(cmd) => match cmd {
            PodCommand::New { name, attach, zone } => {
                pod::create(&cfg.datadir, &name, cli.verbose)?;
                eprintln!("created pod '{name}'");
                if let Some(net_mode) = attach {
                    pod::net_attach(&cfg.datadir, &name, net_mode, zone.as_deref(), cli.verbose)?;
                    eprintln!("attached {net_mode} networking");
                }
                println!("{name}");
            }
            PodCommand::Ls { json, json_pretty } => {
                let json = json || (!json_pretty && cfg.default_output_format == "json");
                let json_pretty =
                    json_pretty || (!json && cfg.default_output_format == "json-pretty");
                let pods = pod::list(&cfg.datadir)?;
                if json || json_pretty {
                    let output = if json_pretty {
                        serde_json::to_string_pretty(&pods)?
                    } else {
                        serde_json::to_string(&pods)?
                    };
                    println!("{output}");
                } else if pods.is_empty() {
                    println!("no pods found");
                } else {
                    let name_w = pods.iter().map(|p| p.name.len()).max().unwrap().max(4);
                    let net_w = pods.iter().map(|p| p.net_mode.len()).max().unwrap().max(3);
                    let zone_w = pods.iter().map(|p| p.net_zone.len()).max().unwrap().max(4);
                    let addr_display: Vec<String> = pods
                        .iter()
                        .map(|p| {
                            if p.addresses.is_empty() {
                                "-".to_string()
                            } else {
                                p.addresses.join(",")
                            }
                        })
                        .collect();
                    let addr_w = addr_display.iter().map(|a| a.len()).max().unwrap().max(9);
                    println!(
                        "{:<name_w$}  ACTIVE  {:<net_w$}  {:<zone_w$}  {:<addr_w$}  CREATED",
                        "NAME", "NET", "ZONE", "ADDRESSES"
                    );
                    for (i, p) in pods.iter().enumerate() {
                        let active = if p.active { "yes" } else { "no" };
                        let net = if p.net_mode.is_empty() {
                            "-"
                        } else {
                            &p.net_mode
                        };
                        let zone = if p.net_zone.is_empty() {
                            "-"
                        } else {
                            &p.net_zone
                        };
                        println!(
                            "{:<name_w$}  {:<6}  {:<net_w$}  {:<zone_w$}  {:<addr_w$}  {}",
                            p.name, active, net, zone, addr_display[i], p.created_at
                        );
                    }
                }
            }
            PodCommand::Rm { names, all, force } => {
                let targets: Vec<String> = if all {
                    let all_pods = pod::list(&cfg.datadir)?;
                    if all_pods.is_empty() {
                        eprintln!("no pods to remove");
                        return Ok(());
                    }
                    if !force {
                        if !interactive {
                            bail!("use -f to confirm removal in non-interactive mode");
                        }
                        let pod_names: Vec<&str> =
                            all_pods.iter().map(|p| p.name.as_str()).collect();
                        eprintln!(
                            "this will remove {} pod{}: {}",
                            pod_names.len(),
                            if pod_names.len() == 1 { "" } else { "s" },
                            pod_names.join(", "),
                        );
                        if !confirm("are you sure? [y/N] ")? {
                            bail!("aborted");
                        }
                    }
                    all_pods.into_iter().map(|p| p.name).collect()
                } else {
                    names
                };
                let mut failed = false;
                for name in &targets {
                    check_interrupted()?;
                    eprintln!("removing pod '{name}'");
                    if let Err(e) = pod::remove(&cfg.datadir, name, force, cli.verbose) {
                        eprintln!("error: {name}: {e}");
                        failed = true;
                    } else {
                        println!("{name}");
                    }
                    if sdme::INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                }
                check_interrupted()?;
                if failed {
                    bail!("some pods could not be removed");
                }
            }
            PodCommand::Net(cmd) => match cmd {
                PodNetCommand::Attach { name, mode, zone } => {
                    pod::net_attach(&cfg.datadir, &name, mode, zone.as_deref(), cli.verbose)?;
                    eprintln!("attached {mode} networking to pod '{name}'");
                    println!("{name}");
                }
                PodNetCommand::Detach { name } => {
                    pod::net_detach(&cfg.datadir, &name, cli.verbose)?;
                    eprintln!("detached networking from pod '{name}'");
                    println!("{name}");
                }
            },
        },
        Command::Kube(cmd) => match cmd {
            KubeCommand::Apply {
                file,
                base_fs,
                timeout,
                pod,
                oci_pod,
                network: net_args,
                security: security_args,
                masked_services,
                no_cache,
            } => {
                system_check::check_systemd_version(255)?;
                let (mut sec, hardened) = parse_security(security_args, &cfg)?;
                validate_pod_args(&cfg.datadir, pod.as_deref())?;
                validate_kube_oci_pod_args(&cfg.datadir, oci_pod.as_deref())?;
                let yaml_content = std::fs::read_to_string(&file)
                    .with_context(|| format!("failed to read {file}"))?;
                let effective_base_fs = base_fs.or_else(|| {
                    if cfg.default_base_fs.is_empty() {
                        None
                    } else {
                        Some(cfg.default_base_fs.clone())
                    }
                });
                let base_fs = effective_base_fs
                    .as_deref()
                    .context("--base-fs is required (or set default with: sdme config set default_base_fs <name>)")?;
                let kube_network = parse_network(net_args)?;
                retain_net_raw_for_dhcp(&mut sec, &kube_network);
                let masked_services =
                    resolve_masked_services(masked_services, &kube_network, &cfg)?;
                let docker_creds = docker_credentials(&cfg);
                let docker_creds_ref = docker_creds.as_ref().map(|(u, t)| (u.as_str(), t.as_str()));
                let mut http = cfg.http_config()?;
                if no_cache {
                    http.manifest_cache_ttl = 0;
                }
                let name = kube::kube_create(
                    &cfg.datadir,
                    &kube::KubeCreateOptions {
                        yaml_content: &yaml_content,
                        base_fs,
                        docker_credentials: docker_creds_ref,
                        cache: &blob_cache,
                        pod: pod.as_deref(),
                        oci_pod: oci_pod.as_deref(),
                        verbose: cli.verbose,
                        default_kube_registry: &cfg.default_kube_registry,
                        network: kube_network,
                        http: &http,
                        auto_gc: cfg.auto_fs_gc,
                        security: sec,
                        hardened,
                        masked_services,
                    },
                )?;
                eprintln!("starting '{name}'");
                let boot_timeout =
                    std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
                start_and_await_boot(&BootConfig {
                    datadir: &cfg.datadir,
                    name: &name,
                    tasks_max: cfg.tasks_max,
                    boot_timeout,
                    stop_timeout: cfg.stop_timeout_terminate,
                    verbose: cli.verbose,
                })?;
                eprintln!("joining '{name}'");
                let shell_opts = containers::ShellOptions {
                    datadir: &cfg.datadir,
                    name: &name,
                    verbose: cli.verbose,
                };
                let status = containers::join(&shell_opts, &[], cfg.join_as_sudo_user)?;
                if !status.success() {
                    let code = status.code().unwrap_or(1);
                    std::process::exit(code);
                }
            }
            KubeCommand::Create {
                file,
                base_fs,
                pod,
                oci_pod,
                network: net_args,
                security: security_args,
                masked_services,
                no_cache,
            } => {
                system_check::check_systemd_version(255)?;
                let (mut sec, hardened) = parse_security(security_args, &cfg)?;
                validate_pod_args(&cfg.datadir, pod.as_deref())?;
                validate_kube_oci_pod_args(&cfg.datadir, oci_pod.as_deref())?;
                let yaml_content = std::fs::read_to_string(&file)
                    .with_context(|| format!("failed to read {file}"))?;
                let effective_base_fs = base_fs.or_else(|| {
                    if cfg.default_base_fs.is_empty() {
                        None
                    } else {
                        Some(cfg.default_base_fs.clone())
                    }
                });
                let base_fs = effective_base_fs
                    .as_deref()
                    .context("--base-fs is required (or set default with: sdme config set default_base_fs <name>)")?;
                let kube_network = parse_network(net_args)?;
                retain_net_raw_for_dhcp(&mut sec, &kube_network);
                let masked_services =
                    resolve_masked_services(masked_services, &kube_network, &cfg)?;
                let docker_creds = docker_credentials(&cfg);
                let docker_creds_ref = docker_creds.as_ref().map(|(u, t)| (u.as_str(), t.as_str()));
                let mut http = cfg.http_config()?;
                if no_cache {
                    http.manifest_cache_ttl = 0;
                }
                let name = kube::kube_create(
                    &cfg.datadir,
                    &kube::KubeCreateOptions {
                        yaml_content: &yaml_content,
                        base_fs,
                        docker_credentials: docker_creds_ref,
                        cache: &blob_cache,
                        pod: pod.as_deref(),
                        oci_pod: oci_pod.as_deref(),
                        verbose: cli.verbose,
                        default_kube_registry: &cfg.default_kube_registry,
                        network: kube_network,
                        http: &http,
                        auto_gc: cfg.auto_fs_gc,
                        security: sec,
                        hardened,
                        masked_services,
                    },
                )?;
                println!("{name}");
            }
            KubeCommand::Delete { name, force } => {
                kube::kube_delete(&cfg.datadir, &name, force, cli.verbose)?;
                println!("{name}");
            }
            KubeCommand::Secret(cmd) => match cmd {
                KubeSecretCommand::Create {
                    name,
                    from_literal,
                    from_file,
                } => {
                    let literals: Vec<(String, String)> = from_literal
                        .iter()
                        .map(|s| {
                            s.split_once('=')
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                                .context(format!(
                                    "invalid --from-literal format: {s} (expected KEY=VALUE)"
                                ))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    let files: Vec<(String, String)> = from_file
                        .iter()
                        .map(|s| {
                            s.split_once('=')
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                                .context(format!(
                                    "invalid --from-file format: {s} (expected KEY=PATH)"
                                ))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    kube::secret::create(&cfg.datadir, &name, &literals, &files)?;
                    println!("{name}");
                }
                KubeSecretCommand::Ls => {
                    let secrets = kube::secret::list(&cfg.datadir)?;
                    if secrets.is_empty() {
                        eprintln!("no secrets");
                        return Ok(());
                    }
                    let name_w = secrets.iter().map(|s| s.name.len()).max().unwrap().max(4);
                    println!("{:<name_w$}  {:>5}  CREATED", "NAME", "KEYS");
                    for s in &secrets {
                        println!("{:<name_w$}  {:>5}  {}", s.name, s.keys, s.created);
                    }
                }
                KubeSecretCommand::Rm { names } => {
                    kube::secret::remove(&cfg.datadir, &names)?;
                    for name in &names {
                        println!("{name}");
                    }
                }
            },
            KubeCommand::Configmap(cmd) => match cmd {
                KubeConfigmapCommand::Create {
                    name,
                    from_literal,
                    from_file,
                } => {
                    let literals: Vec<(String, String)> = from_literal
                        .iter()
                        .map(|s| {
                            s.split_once('=')
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                                .context(format!(
                                    "invalid --from-literal format: {s} (expected KEY=VALUE)"
                                ))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    let files: Vec<(String, String)> = from_file
                        .iter()
                        .map(|s| {
                            s.split_once('=')
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                                .context(format!(
                                    "invalid --from-file format: {s} (expected KEY=PATH)"
                                ))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    kube::configmap::create(&cfg.datadir, &name, &literals, &files)?;
                    println!("{name}");
                }
                KubeConfigmapCommand::Ls => {
                    let configmaps = kube::configmap::list(&cfg.datadir)?;
                    if configmaps.is_empty() {
                        eprintln!("no configmaps");
                        return Ok(());
                    }
                    let name_w = configmaps
                        .iter()
                        .map(|s| s.name.len())
                        .max()
                        .unwrap()
                        .max(4);
                    println!("{:<name_w$}  {:>5}  CREATED", "NAME", "KEYS");
                    for s in &configmaps {
                        println!("{:<name_w$}  {:>5}  {}", s.name, s.keys, s.created);
                    }
                }
                KubeConfigmapCommand::Rm { names } => {
                    kube::configmap::remove(&cfg.datadir, &names)?;
                    for name in &names {
                        println!("{name}");
                    }
                }
            },
        },
        Command::Fs(cmd) => match cmd {
            RootfsCommand::Import {
                source,
                name,
                force,
                install_packages,
                oci_mode,
                base_fs,
                no_cache,
            } => {
                system_check::check_systemd_version(255)?;
                // Fall back to config default_base_fs when --base-fs is not given.
                let effective_base_fs = base_fs.or_else(|| {
                    if cfg.default_base_fs.is_empty() {
                        None
                    } else {
                        Some(cfg.default_base_fs.clone())
                    }
                });
                if effective_base_fs.is_some() && oci_mode == OciMode::Base {
                    bail!("--base-fs cannot be used with --oci-mode=base");
                }
                let docker_creds = docker_credentials(&cfg);
                let docker_creds_ref = docker_creds.as_ref().map(|(u, t)| (u.as_str(), t.as_str()));
                let mut http = cfg.http_config()?;
                if no_cache {
                    http.manifest_cache_ttl = 0;
                }
                rootfs::import(
                    &cfg.datadir,
                    &ImportOptions {
                        source: &source,
                        name: &name,
                        verbose: cli.verbose,
                        force,
                        interactive,
                        install_packages,
                        oci_mode,
                        base_fs: effective_base_fs.as_deref(),
                        docker_credentials: docker_creds_ref,
                        cache: &blob_cache,
                        http,
                        auto_gc: cfg.auto_fs_gc,
                        distros: &cfg.distros,
                    },
                )?;
                println!("{name}");
            }
            RootfsCommand::Ls { json, json_pretty } => {
                let json = json || (!json_pretty && cfg.default_output_format == "json");
                let json_pretty =
                    json_pretty || (!json && cfg.default_output_format == "json-pretty");
                let entries = rootfs::list(&cfg.datadir)?;
                if json || json_pretty {
                    let output = if json_pretty {
                        serde_json::to_string_pretty(&entries)?
                    } else {
                        serde_json::to_string(&entries)?
                    };
                    println!("{output}");
                } else if entries.is_empty() {
                    println!("no root filesystems found");
                } else {
                    let name_w = entries.iter().map(|e| e.name.len()).max().unwrap().max(4);
                    let os_w = entries.iter().map(|e| e.os.len()).max().unwrap().max(2);
                    let show_containers = entries.iter().any(|e| !e.containers.is_empty());
                    print!("{:<name_w$}  {:<os_w$}", "NAME", "OS");
                    if show_containers {
                        print!("  CONTAINERS");
                    }
                    println!("  PATH");
                    for entry in &entries {
                        let path = cfg.datadir.join("fs").join(&entry.name);
                        print!("{:<name_w$}  {:<os_w$}", entry.name, entry.os);
                        if show_containers {
                            print!("  {:<10}", entry.containers.len());
                        }
                        println!("  {}", path.display());
                    }
                }
            }
            RootfsCommand::Rm { names, all, force } => {
                let targets: Vec<String> = if all {
                    let all_names: Vec<String> = rootfs::list(&cfg.datadir)?
                        .into_iter()
                        .map(|e| e.name)
                        .collect();
                    if all_names.is_empty() {
                        eprintln!("no fs entries to remove");
                        return Ok(());
                    }
                    if !force {
                        if !interactive {
                            bail!("use -f to confirm removal in non-interactive mode");
                        }
                        eprintln!(
                            "this will remove {} fs entr{}: {}",
                            all_names.len(),
                            if all_names.len() == 1 { "y" } else { "ies" },
                            all_names.join(", "),
                        );
                        if !confirm("are you sure? [y/N] ")? {
                            bail!("aborted");
                        }
                    }
                    all_names
                } else {
                    names
                };
                let mut failed = false;
                for name in &targets {
                    check_interrupted()?;
                    eprintln!("removing '{name}'");
                    if let Err(e) = rootfs::remove(&cfg.datadir, name, cfg.auto_fs_gc, cli.verbose)
                    {
                        eprintln!("error: {name}: {e}");
                        failed = true;
                    } else {
                        println!("{name}");
                    }
                    if sdme::INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                }
                check_interrupted()?;
                if failed {
                    bail!("some fs entries could not be removed");
                }
            }
            RootfsCommand::Build {
                name,
                config,
                timeout,
                force,
                no_cache,
            } => {
                system_check::check_systemd_version(255)?;
                let boot_timeout = timeout.unwrap_or(cfg.boot_timeout);
                sdme::build::build(
                    &cfg.datadir,
                    &sdme::build::BuildOptions {
                        name: &name,
                        config_path: &config,
                        boot_timeout,
                        tasks_max: cfg.tasks_max,
                        force,
                        auto_gc: cfg.auto_fs_gc,
                        no_cache,
                        verbose: cli.verbose,
                    },
                )?;
                println!("{name}");
            }
            RootfsCommand::Export {
                name,
                output,
                force,
                format,
                size,
                free_space,
                filesystem,
                vm,
                dns,
                net_ifaces,
                root_password,
                ssh_key,
                swap,
                hostname,
                install_packages,
                timezone,
            } => {
                // Parse fs: prefix for rootfs catalogue export vs container export.
                let source = if let Some(fs_name) = name.strip_prefix("fs:") {
                    let fs_dir = cfg.datadir.join("fs").join(fs_name);
                    if !fs_dir.is_dir() {
                        let state_file = cfg.datadir.join("state").join(fs_name);
                        if state_file.exists() {
                            bail!(
                                "rootfs '{fs_name}' does not exist; \
                                 did you mean '{fs_name}' (without the fs: prefix) \
                                 to export container '{fs_name}'?"
                            );
                        }
                        bail!("rootfs not found: {fs_name}");
                    }
                    export::ExportSource::Rootfs(fs_name.to_string())
                } else {
                    let state_file = cfg.datadir.join("state").join(&name);
                    if !state_file.exists() {
                        let fs_dir = cfg.datadir.join("fs").join(&name);
                        if fs_dir.is_dir() {
                            bail!(
                                "container '{name}' does not exist; \
                                 did you mean fs:{name} to export rootfs '{name}'?"
                            );
                        }
                        bail!("container does not exist: {name}");
                    }
                    export::ExportSource::Container(name.clone())
                };

                let fmt = export::detect_format(&output, format.as_deref())?;
                let fs_str = filesystem.as_deref().unwrap_or(&cfg.default_export_fs);
                let fmt = match fmt {
                    export::ExportFormat::Raw(_) => {
                        let fs_type = match fs_str {
                            "ext4" => export::RawFs::Ext4,
                            "btrfs" => export::RawFs::Btrfs,
                            other => bail!("unknown filesystem '{other}': expected ext4 or btrfs"),
                        };
                        export::ExportFormat::Raw(fs_type)
                    }
                    _ => {
                        if filesystem.is_some() {
                            bail!("--filesystem only applies to raw disk image format");
                        }
                        fmt
                    }
                };

                // Build VM options if --vm is specified.
                let vm_opts = if vm {
                    if !matches!(fmt, export::ExportFormat::Raw(_)) {
                        bail!("--vm only applies to raw disk image format");
                    }
                    let ssh_key = match ssh_key {
                        Some(key) => {
                            let path = std::path::Path::new(&key);
                            if path.is_file() {
                                Some(std::fs::read_to_string(path).with_context(|| {
                                    format!("failed to read SSH key file: {}", path.display())
                                })?)
                            } else {
                                Some(key)
                            }
                        }
                        None => None,
                    };
                    let swap_size = match swap {
                        Some(s) => sdme::parse_size(&s).context("invalid --swap size")?,
                        None => 0,
                    };
                    let hostname = hostname.unwrap_or_else(|| name.clone());
                    Some(export::VmOptions {
                        hostname,
                        nameservers: dns,
                        net_ifaces,
                        root_password,
                        ssh_key,
                        swap_size,
                        install_packages,
                        interactive,
                        distros: cfg.distros.clone(),
                    })
                } else {
                    None
                };

                let output_path = std::path::PathBuf::from(&output);
                let free_space_str = free_space
                    .as_deref()
                    .unwrap_or(&cfg.default_export_free_space);
                let free_space =
                    sdme::parse_size(free_space_str).context("invalid --free-space value")?;
                if size.is_some() && free_space > 0 {
                    eprintln!(
                        "warning: --size overrides auto-calculation; \
                         --free-space is ignored"
                    );
                }
                let export_opts = export::ExportOptions {
                    format: &fmt,
                    size: size.as_deref(),
                    free_space,
                    vm_opts: vm_opts.as_ref(),
                    verbose: cli.verbose,
                    force,
                    timezone: timezone.as_deref(),
                };
                let result = export::export(
                    &cfg.datadir,
                    &source,
                    &output_path,
                    &export_opts,
                    cfg.auto_fs_gc,
                )?;
                println!("{} ({})", output_path.display(), result.summary());
            }
            RootfsCommand::Cache(cmd) => match cmd {
                CacheCommand::Info => {
                    let info = blob_cache.info()?;
                    println!("directory = {}", info.dir.display());
                    println!("blobs = {}", info.blob_count);
                    println!(
                        "size = {} ({})",
                        oci::cache::format_size(info.total_size),
                        info.total_size
                    );
                    println!(
                        "max_size = {} ({})",
                        oci::cache::format_size(info.max_size),
                        info.max_size
                    );
                    if !blob_cache.is_enabled() {
                        println!("status = disabled");
                    }
                }
                CacheCommand::Ls => {
                    let entries = blob_cache.list()?;
                    if entries.is_empty() {
                        eprintln!("no cached blobs");
                    } else {
                        let digest_w = 19; // "sha256:" + 12 hex chars
                        println!("{:<digest_w$}  {:>10}  LAST ACCESS", "DIGEST", "SIZE");
                        for entry in &entries {
                            let short = if entry.digest.len() > 19 {
                                &entry.digest[..19]
                            } else {
                                &entry.digest
                            };
                            println!(
                                "{:<digest_w$}  {:>10}  {}",
                                short,
                                oci::cache::format_size(entry.size),
                                entry.last_access
                            );
                        }
                    }
                }
                CacheCommand::Clean { all } => {
                    let freed = blob_cache.clean(all, cli.verbose)?;
                    if freed > 0 {
                        eprintln!("freed {}", oci::cache::format_size(freed));
                    } else {
                        eprintln!("nothing to clean");
                    }
                }
            },
            RootfsCommand::Gc => {
                let fs_dir = cfg.datadir.join("fs");
                let count = sdme::txn::gc(&fs_dir, cli.verbose)?;
                if count == 0 {
                    eprintln!("no stale transactions found");
                } else {
                    eprintln!("cleaned {count} stale transaction(s)");
                }
            }
        },
        Command::Prune {
            dry_run,
            force,
            except,
        } => {
            let all_items = prune::analyze(&cfg.datadir, &cfg.default_base_fs)?;

            let (prunable, excluded): (Vec<_>, Vec<_>) = all_items
                .into_iter()
                .partition(|item| !prune::is_excluded(item, &except));

            if prunable.is_empty() {
                eprintln!("nothing to prune");
                return Ok(());
            }

            prune::display(&prunable, excluded.len(), &cfg.default_base_fs);

            if dry_run {
                return Ok(());
            }

            if !force {
                if !interactive {
                    bail!("use -f to confirm pruning in non-interactive mode");
                }
                if !confirm("proceed? [y/N] ")? {
                    bail!("aborted");
                }
            }

            let (succeeded, errors) =
                prune::execute(&prunable, &cfg.datadir, cfg.auto_fs_gc, cli.verbose);

            // Propagate signal exit code (130 for SIGINT) before error summary.
            check_interrupted()?;

            for (name, err) in &errors {
                eprintln!("error: {name}: {err}");
            }

            if errors.is_empty() {
                eprintln!("pruned {succeeded} item(s)");
            } else {
                eprintln!("pruned {succeeded} item(s), {} failed", errors.len());
                bail!("some items could not be pruned");
            }
        }
        Command::Upgrade {
            check,
            yes,
            version,
        } => {
            sdme::update::run_upgrade(
                &cfg,
                sdme::update::UpgradeOptions {
                    assume_yes: yes,
                    check_only: check,
                    version_override: version.as_deref(),
                    verbose: cli.verbose,
                    interactive,
                },
            )?;
        }
    }

    sdme::update::maybe_spawn_background_check(&cfg, skip_update_probe, cli.verbose);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sdme::network::NetworkConfig;
    use std::fs;

    /// Create a temp rootfs dir with an oci/apps/app/ports file.
    fn make_rootfs_with_ports(name: &str, ports_content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sdme-test-autowire-{}-{:?}-{name}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("oci/apps/app")).unwrap();
        fs::write(dir.join("oci/apps/app/ports"), ports_content).unwrap();
        dir
    }

    #[test]
    fn test_auto_wire_oci_ports_private_network() {
        let rootfs = make_rootfs_with_ports("priv", "80/tcp\n443/tcp\n");
        let mut network = NetworkConfig {
            private_network: true,
            ..Default::default()
        };

        auto_wire_oci_ports(&rootfs, &mut network);

        assert_eq!(network.ports.len(), 2);
        assert!(network.ports.contains(&"tcp:80:80".to_string()));
        assert!(network.ports.contains(&"tcp:443:443".to_string()));

        let _ = fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn test_auto_wire_oci_ports_skips_user_specified() {
        let rootfs = make_rootfs_with_ports("skip", "80/tcp\n443/tcp\n8080/tcp\n");
        let mut network = NetworkConfig {
            private_network: true,
            ports: vec!["tcp:9090:80".to_string()], // User already mapped container port 80
            ..Default::default()
        };

        auto_wire_oci_ports(&rootfs, &mut network);

        // Port 80 should NOT be added (user already specified it).
        // Ports 443 and 8080 should be added.
        assert_eq!(network.ports.len(), 3); // 1 user + 2 auto
        assert!(network.ports.contains(&"tcp:9090:80".to_string())); // user's original
        assert!(network.ports.contains(&"tcp:443:443".to_string()));
        assert!(network.ports.contains(&"tcp:8080:8080".to_string()));
        // Should NOT have a duplicate mapping for port 80.
        assert!(
            !network.ports.contains(&"tcp:80:80".to_string()),
            "should not auto-forward port 80 when user already specified it"
        );

        let _ = fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn test_auto_wire_oci_ports_host_network_no_forwarding() {
        let rootfs = make_rootfs_with_ports("host", "80/tcp\n443/tcp\n");
        let mut network = NetworkConfig {
            private_network: false,
            ..Default::default()
        };

        auto_wire_oci_ports(&rootfs, &mut network);

        // Host network: no ports should be added.
        assert!(
            network.ports.is_empty(),
            "host network should not add port forwarding rules"
        );

        let _ = fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn test_auto_wire_oci_ports_no_ports_file() {
        let dir = std::env::temp_dir().join(format!(
            "sdme-test-autowire-{}-{:?}-nofile",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // No oci/ports file.

        let mut network = NetworkConfig {
            private_network: true,
            ..Default::default()
        };

        auto_wire_oci_ports(&dir, &mut network);

        assert!(network.ports.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_auto_wire_oci_ports_empty_file() {
        let rootfs = make_rootfs_with_ports("empty", "");
        let mut network = NetworkConfig {
            private_network: true,
            ..Default::default()
        };

        auto_wire_oci_ports(&rootfs, &mut network);

        assert!(network.ports.is_empty());

        let _ = fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn test_auto_wire_oci_ports_udp() {
        let rootfs = make_rootfs_with_ports("udp", "53/udp\n80/tcp\n");
        let mut network = NetworkConfig {
            private_network: true,
            ..Default::default()
        };

        auto_wire_oci_ports(&rootfs, &mut network);

        assert_eq!(network.ports.len(), 2);
        assert!(network.ports.contains(&"udp:53:53".to_string()));
        assert!(network.ports.contains(&"tcp:80:80".to_string()));

        let _ = fs::remove_dir_all(&rootfs);
    }
}
