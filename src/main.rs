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
    check_interrupted, config, confirm, containers, export, kube, oci, pod, rootfs, security,
    system_check, systemd, BindConfig, EnvConfig, NetworkConfig, ResourceLimits, SecurityConfig,
};

#[derive(Parser)]
#[command(
    name = "sdme",
    version,
    about = "Lightweight systemd-nspawn containers with overlayfs"
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

/// Network configuration CLI arguments (shared by create/new).
#[derive(clap::Args, Default)]
struct NetworkArgs {
    /// Use private network namespace (isolated from host)
    #[arg(long)]
    private_network: bool,

    /// Create virtual ethernet link (implies --private-network)
    #[arg(long)]
    network_veth: bool,

    /// Connect to host bridge (implies --private-network)
    #[arg(long)]
    network_bridge: Option<String>,

    /// Join named network zone for inter-container networking (implies --private-network)
    #[arg(long)]
    network_zone: Option<String>,

    /// Forward port [PROTO:]HOST[:CONTAINER] (implies --private-network, repeatable)
    #[arg(long = "port", short = 'p')]
    ports: Vec<String>,
}

/// Bind mount and environment variable CLI arguments (shared by create/new).
#[derive(clap::Args, Default)]
struct MountArgs {
    /// Bind mount HOST:CONTAINER[:ro] (repeatable)
    #[arg(long = "bind", short = 'b')]
    binds: Vec<String>,

    /// Set environment variable KEY=VALUE (repeatable)
    #[arg(long = "env", short = 'e')]
    envs: Vec<String>,
}

/// Security hardening CLI arguments (shared by create/new).
#[derive(clap::Args, Default)]
struct SecurityArgs {
    /// Enable user namespace isolation (container root != host root)
    #[arg(short = 'u', long)]
    userns: bool,

    /// Drop a capability (e.g. CAP_SYS_PTRACE, repeatable)
    #[arg(long = "drop-capability")]
    drop_caps: Vec<String>,

    /// Add a capability (e.g. CAP_NET_ADMIN, repeatable)
    #[arg(long = "capability")]
    add_caps: Vec<String>,

    /// Prevent gaining privileges via setuid binaries or file capabilities
    #[arg(long)]
    no_new_privileges: bool,

    /// Mount the container rootfs read-only
    #[arg(long)]
    read_only: bool,

    /// Seccomp system call filter (e.g. @system-service, ~@mount, repeatable)
    #[arg(long = "system-call-filter")]
    system_call_filter: Vec<String>,

    /// AppArmor profile to confine the container
    #[arg(long)]
    apparmor_profile: Option<String>,

    /// Enable hardened security defaults (userns, private-network, no-new-privileges,
    /// drops CAP_SYS_PTRACE, CAP_NET_RAW, CAP_SYS_RAWIO, CAP_SYS_BOOT)
    #[arg(long)]
    hardened: bool,

    /// Maximum security (hardened + Docker-equivalent cap drops, seccomp, AppArmor).
    /// Retains CAP_SYS_ADMIN for systemd init. Requires the sdme-default AppArmor
    /// profile to be loaded (see: sdme config apparmor-profile --help)
    #[arg(long)]
    strict: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Manage configuration
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Create a new container
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
    },

    /// Run a command in a running container
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
    Ps,

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

    /// Manage root filesystems
    #[command(name = "fs", subcommand)]
    Fs(RootfsCommand),

    /// Manage pod network namespaces
    #[command(name = "pod", subcommand)]
    Pod(PodCommand),

    /// Manage Kubernetes-compatible pods (experimental)
    #[command(name = "kube", subcommand)]
    Kube(KubeCommand),
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum RootfsCommand {
    /// Import a root filesystem from a directory, tarball, URL, OCI image, registry image, or QCOW2 disk image
    #[command(after_long_help = "\
OCI REGISTRY IMAGES:
    When the source is an OCI registry image (e.g. docker.io/ubuntu:24.04),
    sdme pulls the image layers and extracts the root filesystem.

    --oci-mode controls how the image is classified:

      auto (default)  Auto-detect from image config. Base OS images have no
                      entrypoint, a shell as default command, and no exposed
                      ports. Everything else is an application image.

      base            Force base OS mode. The rootfs goes through systemd
                      detection and package installation (apt/dnf). Use this
                      for OS images that the heuristic misclassifies.

      app             Force application mode. Requires --base-fs to
                      specify a systemd-capable rootfs as the base layer.
                      The OCI rootfs is placed under /oci/apps/{name}/root and a systemd
                      unit is generated to run the application.

    Examples:
      sdme fs import ubuntu docker.io/ubuntu -v --install-packages=yes
      sdme fs import nginx docker.io/nginx --base-fs=ubuntu -v
      sdme fs import myapp ghcr.io/org/app:v1 --oci-mode=app --base-fs=ubuntu")]
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
    },
    /// List imported root filesystems
    Ls,
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
    #[command(after_long_help = "\
BUILD CONFIG FORMAT:
    The build config is a line-oriented text file with three directives:

        FROM <rootfs>       Base rootfs (must be first, required, only once)
        RUN <command>       Run a shell command inside the container
        COPY <src> <dst>    Copy a host file or directory into the rootfs

    Lines starting with # and blank lines are ignored.
    RUN commands execute via /bin/sh -c and support pipes, &&, etc.
    COPY stops the container (if running) and writes directly to the
    overlayfs upper layer. Paths with '..' components are rejected.

    COPY does not support these destinations: /tmp, /run, /dev/shm.
    systemd mounts tmpfs over them at boot, which hides files written
    to the overlayfs upper layer. Overlayfs opaque directories are also
    rejected. Use a different path (e.g. /root, /opt, /srv).

EXAMPLE:
    # Import a base rootfs
    sudo debootstrap --include=dbus,systemd noble /tmp/ubuntu
    sudo sdme fs import ubuntu /tmp/ubuntu

    # Create a build config
    cat << EOF > examplefs.conf
    FROM ubuntu
    RUN apt-get update
    RUN apt-get install -y systemd-container
    COPY ./target/release/sdme /usr/local/bin/sdme
    EOF

    # Build and use
    sudo sdme fs build examplefs examplefs.conf
    sudo sdme new -r examplefs")]
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
    },
    /// Export a root filesystem or container to a directory, tarball, or disk image
    Export {
        /// Name of the rootfs or container to export
        name: String,
        /// Output path (format auto-detected from extension, or use --fmt)
        output: String,
        /// Export a container's merged rootfs instead of an imported rootfs
        #[arg(long)]
        container: bool,
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
    #[command(
        name = "apparmor-profile",
        after_long_help = "\
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
    https://gitlab.com/apparmor/apparmor/-/wikis/Documentation"
    )]
    AppArmorProfile,
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum PodCommand {
    /// Create a new pod network namespace
    New {
        /// Pod name
        name: String,
    },
    /// List pods
    Ls,
    /// Remove one or more pods
    Rm {
        /// Pod names
        #[arg(required = true)]
        names: Vec<String>,
        /// Force removal even if containers reference the pod
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
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
        security: SecurityArgs,

        /// Systemd services to mask in the overlayfs upper layer (comma-separated, overrides config default)
        #[arg(long, value_delimiter = ',')]
        masked_services: Option<Vec<String>>,
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
        security: SecurityArgs,

        /// Systemd services to mask in the overlayfs upper layer (comma-separated, overrides config default)
        #[arg(long, value_delimiter = ',')]
        masked_services: Option<Vec<String>>,
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

fn for_each_container(
    datadir: &std::path::Path,
    targets: &[String],
    verb: &str,
    past: &str,
    action: impl Fn(&str) -> Result<()>,
) -> Result<()> {
    let mut failed = false;
    for input in targets {
        check_interrupted()?;
        let name = match containers::resolve_name(datadir, input) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("error: {input}: {e}");
                failed = true;
                continue;
            }
        };
        eprintln!("{verb} '{name}'");
        if let Err(e) = action(&name) {
            eprintln!("error: {name}: {e}");
            failed = true;
        } else {
            println!("{name}");
        }
    }
    if failed {
        bail!("some containers could not be {past}");
    }
    Ok(())
}

/// Start a container and wait for it to boot.
///
/// On boot failure (or Ctrl+C), resets the interrupt flag and stops the
/// container so it doesn't linger in a half-booted state. Used by `start`
/// and `join --start`.
fn start_and_await_boot(
    datadir: &std::path::Path,
    name: &str,
    tasks_max: u32,
    boot_timeout: std::time::Duration,
    config_boot_timeout: u64,
    verbose: bool,
) -> Result<()> {
    systemd::start(datadir, name, tasks_max, config_boot_timeout, verbose)?;
    if let Err(e) = systemd::await_boot(name, boot_timeout, verbose) {
        sdme::reset_interrupt();
        eprintln!("boot failed, stopping '{name}'");
        let _ = containers::stop(name, containers::StopMode::Terminate, 30, verbose);
        return Err(e);
    }
    Ok(())
}

/// Build a `ResourceLimits` from CLI flags (for `create` / `new`).
///
/// `None` means the flag was not provided; the limit is left unset.
fn parse_limits(
    memory: Option<String>,
    cpus: Option<String>,
    cpu_weight: Option<String>,
) -> Result<ResourceLimits> {
    let limits = ResourceLimits {
        memory,
        cpus,
        cpu_weight,
    };
    limits.validate()?;
    Ok(limits)
}

/// Build a `NetworkConfig` from CLI flags (for `create` / `new`).
///
/// Options that imply `--private-network` automatically enable it.
fn parse_network(args: NetworkArgs) -> Result<NetworkConfig> {
    // Auto-enable private_network if any option that requires it is set
    let private_network = args.private_network
        || args.network_veth
        || args.network_bridge.is_some()
        || args.network_zone.is_some()
        || !args.ports.is_empty();

    let network = NetworkConfig {
        private_network,
        network_veth: args.network_veth,
        network_bridge: args.network_bridge,
        network_zone: args.network_zone,
        ports: args.ports,
    };
    network.validate()?;
    Ok(network)
}

/// Build `BindConfig` and `EnvConfig` from CLI flags (for `create` / `new`).
fn parse_mounts(args: MountArgs) -> Result<(BindConfig, EnvConfig)> {
    let binds = BindConfig::from_cli_args(args.binds)?;
    binds.validate()?;
    let envs = EnvConfig { vars: args.envs };
    envs.validate()?;
    Ok((binds, envs))
}

/// Validate `--oci-env` values using the same rules as `-e`/`--env`.
fn validate_oci_envs(envs: Vec<String>) -> Result<Vec<String>> {
    let tmp = EnvConfig { vars: envs };
    tmp.validate()?;
    Ok(tmp.vars)
}

/// Build a `SecurityConfig` from CLI flags (for `create` / `new`).
///
/// When `--hardened` is set, merges the config's `hardened_drop_caps` with
/// any explicit flags. When `--strict` is set, applies Docker-equivalent
/// restrictions (implies `--hardened`). Explicit `--capability` and
/// `--drop-capability` flags take priority over both presets.
fn parse_security(args: SecurityArgs, cfg: &config::Config) -> Result<(SecurityConfig, bool)> {
    let mut drop_caps: Vec<String> = args
        .drop_caps
        .iter()
        .map(|c| security::normalize_cap(c))
        .collect();
    let add_caps: Vec<String> = args
        .add_caps
        .iter()
        .map(|c| security::normalize_cap(c))
        .collect();
    let mut userns = args.userns;
    let mut no_new_privileges = args.no_new_privileges;
    let mut system_call_filter = args.system_call_filter;
    let mut apparmor_profile = args.apparmor_profile;

    // --strict implies --hardened and adds Docker-equivalent restrictions.
    let strict = args.strict;
    let hardened = args.hardened || strict;

    if strict {
        userns = true;
        no_new_privileges = true;

        // Drop all caps except Docker's default set + CAP_SYS_ADMIN.
        for cap in security::STRICT_DROP_CAPS {
            let cap = cap.to_string();
            if !add_caps.contains(&cap) && !drop_caps.contains(&cap) {
                drop_caps.push(cap);
            }
        }

        // Add seccomp filters if none were explicitly provided.
        if system_call_filter.is_empty() {
            system_call_filter = security::STRICT_SYSCALL_FILTERS
                .iter()
                .map(|s| s.to_string())
                .collect();
        }

        // Set AppArmor profile if not explicitly provided.
        if apparmor_profile.is_none() {
            apparmor_profile = Some(security::STRICT_APPARMOR_PROFILE.to_string());
        }
    } else if hardened {
        userns = true;
        no_new_privileges = true;

        // Merge hardened drop_caps from config.
        let hardened_caps: Vec<String> = if cfg.hardened_drop_caps.is_empty() {
            Vec::new()
        } else {
            cfg.hardened_drop_caps
                .split(',')
                .map(|c| security::normalize_cap(c.trim()))
                .collect()
        };
        for cap in hardened_caps {
            // Don't add if user explicitly re-adds via --capability.
            if !add_caps.contains(&cap) && !drop_caps.contains(&cap) {
                drop_caps.push(cap);
            }
        }
    }

    let sec = SecurityConfig {
        userns,
        drop_caps,
        add_caps,
        no_new_privileges,
        read_only: args.read_only,
        system_call_filter,
        apparmor_profile,
    };
    sec.validate()?;
    Ok((sec, hardened))
}

/// Extract Docker Hub credentials from config, if both user and token are set.
/// Display distro prehook configuration, showing effective commands
/// (overrides or built-in defaults) for all configurable families.
fn display_distro_hooks(cfg: &config::Config) {
    use sdme::export::{builtin_export_prehook, builtin_export_vm_prehook};
    use sdme::import::builtin_import_prehook;
    use sdme::rootfs::DistroFamily;

    let families = [
        DistroFamily::Debian,
        DistroFamily::Fedora,
        DistroFamily::Arch,
        DistroFamily::Suse,
    ];

    for family in &families {
        let key = family.config_key();
        let overrides = cfg.distros.get(key);

        let (import_cmds, import_custom) = match overrides.and_then(|d| d.import_prehook.as_ref()) {
            Some(cmds) => (cmds.clone(), true),
            None => (builtin_import_prehook(family), false),
        };
        let (export_cmds, export_custom) = match overrides.and_then(|d| d.export_prehook.as_ref()) {
            Some(cmds) => (cmds.clone(), true),
            None => (builtin_export_prehook(family), false),
        };
        let (export_vm_cmds, export_vm_custom) =
            match overrides.and_then(|d| d.export_vm_prehook.as_ref()) {
                Some(cmds) => (cmds.clone(), true),
                None => (builtin_export_vm_prehook(family), false),
            };

        println!("\n[distros.{key}]");
        let tag = if import_custom { " (custom)" } else { "" };
        print!("import_prehook{tag} = ");
        print_hook_commands(&import_cmds);
        let tag = if export_custom { " (custom)" } else { "" };
        print!("export_prehook{tag} = ");
        print_hook_commands(&export_cmds);
        let tag = if export_vm_custom { " (custom)" } else { "" };
        print!("export_vm_prehook{tag} = ");
        print_hook_commands(&export_vm_cmds);
    }
}

/// Print a command list in a human-readable multi-line format.
fn print_hook_commands(cmds: &[String]) {
    if cmds.is_empty() {
        println!("[]");
        return;
    }
    if cmds.len() == 1 {
        println!("{:?}", cmds);
        return;
    }
    println!("[");
    for (i, cmd) in cmds.iter().enumerate() {
        let comma = if i + 1 < cmds.len() { "," } else { "" };
        println!("  {cmd:?}{comma}");
    }
    println!("]");
}

fn docker_credentials(cfg: &config::Config) -> Option<(String, String)> {
    if cfg.docker_user.is_empty() || cfg.docker_token.is_empty() {
        return None;
    }
    Some((cfg.docker_user.clone(), cfg.docker_token.clone()))
}

/// Parse the comma-separated `host_rootfs_opaque_dirs` config value into a Vec.
fn parse_opaque_dirs_config(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',').map(|p| p.trim().to_string()).collect()
}

/// Resolve opaque dirs for container creation.
///
/// If the user passed explicit `-o` flags, those take priority.
/// Otherwise, for host-rootfs containers (no `-r`), apply the config defaults.
/// For imported-rootfs containers, return an empty vec.
fn resolve_opaque_dirs(
    cli_dirs: Vec<String>,
    is_host_rootfs: bool,
    cfg: &config::Config,
) -> Vec<String> {
    if !cli_dirs.is_empty() {
        cli_dirs
    } else if is_host_rootfs {
        parse_opaque_dirs_config(&cfg.host_rootfs_opaque_dirs)
    } else {
        Vec::new()
    }
}

/// Resolve which systemd services to mask at create time.
///
/// If the user passed explicit `--masked-services`, use that as-is.
/// Otherwise, use the config default. When using defaults and
/// `--network-zone` is set, automatically remove `systemd-resolved.service`
/// from the list (zones enable inter-container DNS via resolved).
fn resolve_masked_services(
    cli_masked: Option<Vec<String>>,
    network: &NetworkConfig,
    cfg: &config::Config,
) -> anyhow::Result<Vec<String>> {
    let list = if let Some(explicit) = cli_masked {
        // Explicit override: use as-is (even if empty).
        explicit.into_iter().filter(|s| !s.is_empty()).collect()
    } else {
        // Config defaults.
        let mut list: Vec<String> = cfg
            .default_create_masked_services
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        // Auto-unmask resolved for --network-zone containers.
        if network.network_zone.is_some() {
            list.retain(|s| s != "systemd-resolved.service");
        }
        list
    };
    for svc in &list {
        if svc.contains('/') || svc.contains("..") {
            anyhow::bail!("invalid masked service name: {svc:?}");
        }
    }
    Ok(list)
}

/// Auto-wire OCI port forwarding from the rootfs `/oci/ports` file.
///
/// When private network is enabled, merges OCI-declared ports into the
/// network config (skipping any already covered by user `--port` flags).
/// When using host network, prints an informational message instead.
fn auto_wire_oci_ports(rootfs_path: &std::path::Path, network: &mut NetworkConfig) {
    let oci_ports = oci::rootfs::read_oci_ports(rootfs_path);
    if oci_ports.is_empty() {
        return;
    }

    if network.private_network {
        // Collect container port numbers already specified by the user.
        // User ports may be "[proto:]host[:container]"; container port
        // is the last colon-separated segment (or the only one).
        let user_container_ports: std::collections::HashSet<u16> = network
            .ports
            .iter()
            .filter_map(|p| p.rsplit(':').next().and_then(|s| s.parse::<u16>().ok()))
            .collect();

        let mut added = Vec::new();
        for port in &oci_ports {
            // Extract container port from "PROTO:HOST:CONTAINER"
            let container_port: Option<u16> = port.rsplit(':').next().and_then(|s| s.parse().ok());
            if let Some(cp) = container_port {
                if !user_container_ports.contains(&cp) {
                    network.ports.push(port.clone());
                    added.push(port.clone());
                }
            }
        }

        if !added.is_empty() {
            eprintln!("auto-forwarding OCI ports: {}", added.join(", "));
        }
    } else {
        // Display as "PORT/PROTO" for readability (e.g. "8080/tcp").
        let display: Vec<String> = oci_ports
            .iter()
            .filter_map(|p| {
                // Format is "PROTO:HOST:CONTAINER"; show "CONTAINER/PROTO"
                let parts: Vec<&str> = p.splitn(3, ':').collect();
                if parts.len() == 3 {
                    Some(format!("{}/{}", parts[2], parts[0]))
                } else {
                    None
                }
            })
            .collect();
        eprintln!(
            "OCI image exposes ports: {} (host network, no forwarding needed)",
            display.join(", ")
        );
    }
}

/// Read OCI volume paths from a rootfs, or return an empty vec.
///
/// Resolves the rootfs path and reads `/oci/volumes`. Prints the
/// auto-mounting message when volumes are found.
fn read_oci_volumes_for_rootfs(
    datadir: &std::path::Path,
    rootfs_name: Option<&str>,
    no_oci_volumes: bool,
) -> Result<Vec<String>> {
    if no_oci_volumes {
        return Ok(Vec::new());
    }
    let rootfs_name = match rootfs_name {
        Some(n) => n,
        None => return Ok(Vec::new()),
    };
    let rootfs_path = containers::resolve_rootfs(datadir, Some(rootfs_name))?;
    let volumes = oci::rootfs::read_oci_volumes(&rootfs_path);
    if !volumes.is_empty() {
        eprintln!("auto-mounting OCI volumes: {}", volumes.join(", "));
    }
    Ok(volumes)
}

/// Resolve the OCI app name for a container.
///
/// If `explicit` is provided, validates it against known apps and returns it.
/// Otherwise checks the state file for `OCI_APP` or `KUBE_CONTAINERS` keys,
/// then falls back to auto-detecting from the rootfs.
///
/// For kube containers with multiple apps and no explicit selection, returns
/// an error listing available container names.
fn resolve_oci_app_name(
    datadir: &std::path::Path,
    name: &str,
    explicit: Option<&str>,
) -> Result<String> {
    let state_path = datadir.join("state").join(name);
    if let Ok(state) = sdme::State::read_from(&state_path) {
        // If an explicit app name was given, validate it.
        if let Some(app) = explicit {
            if let Some(kube_containers) = state.get("KUBE_CONTAINERS") {
                let names: Vec<&str> = kube_containers.split(',').collect();
                if names.contains(&app) {
                    return Ok(app.to_string());
                }
                bail!(
                    "container '{app}' not found in kube pod '{name}'; available: {}",
                    kube_containers
                );
            }
            // For non-kube OCI containers, validate against OCI_APP.
            if let Some(oci_app) = state.get("OCI_APP") {
                if !oci_app.is_empty() && oci_app == app {
                    return Ok(app.to_string());
                }
            }
            // Fall back: trust the explicit name (it may exist in rootfs).
            return Ok(app.to_string());
        }

        if let Some(app) = state.get("OCI_APP") {
            if !app.is_empty() {
                return Ok(app.to_string());
            }
        }
        // For kube containers, require --oci NAME when multiple containers exist.
        if let Some(kube_containers) = state.get("KUBE_CONTAINERS") {
            let names: Vec<&str> = kube_containers
                .split(',')
                .filter(|s| !s.is_empty())
                .collect();
            if names.len() == 1 {
                return Ok(names[0].to_string());
            }
            bail!(
                "kube pod '{name}' has multiple containers: {}; use --oci NAME to select one",
                kube_containers
            );
        }
        // Fall back to auto-detection from rootfs.
        if let Some(rootfs_name) = state.get("ROOTFS") {
            if !rootfs_name.is_empty() {
                let rootfs_path = datadir.join("fs").join(rootfs_name);
                if let Some(app) = oci::rootfs::detect_oci_app_name(&rootfs_path) {
                    return Ok(app);
                }
            }
        }
    }
    bail!("cannot determine OCI app name for container '{name}'; no OCI_APP in state file and no /oci/apps/ in rootfs")
}

/// Validate `--pod` constraints before creating a container.
///
/// Checks that:
/// - The pod exists in the catalogue
/// - `--pod` is not combined with user namespace isolation (`--userns`,
///   `--hardened`). The kernel blocks `setns(CLONE_NEWNET)` from a child
///   user namespace into the pod's netns (owned by the init userns).
///   Use `--oci-pod` instead: its inner systemd drop-in joins the pod
///   netns from inside the container, avoiding the cross-userns restriction.
fn validate_pod_args(
    datadir: &std::path::Path,
    pod_name: Option<&str>,
    userns: bool,
) -> Result<()> {
    let pod_name = match pod_name {
        Some(n) => n,
        None => return Ok(()),
    };

    if !pod::exists(datadir, pod_name) {
        bail!("pod not found: {pod_name}");
    }

    if userns {
        bail!(
            "--pod is incompatible with user namespace isolation (--userns, --hardened);\n\
             the kernel blocks setns(CLONE_NEWNET) across user namespace boundaries.\n\
             Use --oci-pod instead, which joins the pod netns from inside the container."
        );
    }

    Ok(())
}

/// Validate `--oci-pod` constraints before creating a container.
///
/// Checks that:
/// - The pod exists in the catalogue
/// - The rootfs is an OCI app rootfs (contains an `sdme-oci-*.service` unit)
/// - Private network is enabled (required for `NetworkNamespacePath=` inside
///   the container; nspawn strips `CAP_NET_ADMIN` on host-network containers,
///   which prevents systemd from calling `setns(CLONE_NEWNET)`)
fn validate_oci_pod_args(
    datadir: &std::path::Path,
    oci_pod: Option<&str>,
    rootfs: Option<&str>,
    private_network: bool,
) -> Result<()> {
    let pod_name = match oci_pod {
        Some(n) => n,
        None => return Ok(()),
    };

    if !pod::exists(datadir, pod_name) {
        bail!("pod not found: {pod_name}");
    }

    if !private_network {
        bail!(
            "--oci-pod requires --private-network (or --hardened/--strict which imply it); \
             without a private network namespace, systemd-nspawn strips CAP_NET_ADMIN \
             and the inner NetworkNamespacePath= directive cannot work"
        );
    }

    // Validate that the rootfs is an OCI app rootfs.
    let rootfs_name = match rootfs {
        Some(name) => name,
        None => bail!("--oci-pod requires an OCI app rootfs (use -r/--fs)"),
    };
    let rootfs_path = datadir.join("fs").join(rootfs_name);
    // Check for any sdme-oci-*.service file.  On most distros the unit
    // lives in etc/systemd/system, but on NixOS it is placed in
    // etc/systemd/system.control because NixOS activation replaces
    // /etc/systemd/system with an immutable symlink to the Nix store
    // (see oci::app::systemd_unit_dir).  We check both directories so
    // this validation works regardless of the base distro.
    let has_oci_service = ["etc/systemd/system", "etc/systemd/system.control"]
        .iter()
        .any(|dir| {
            rootfs_path
                .join(dir)
                .read_dir()
                .ok()
                .and_then(|entries| {
                    entries.filter_map(|e| e.ok()).find(|e| {
                        let name = e.file_name();
                        let name = name.to_string_lossy();
                        name.starts_with("sdme-oci-") && name.ends_with(".service")
                    })
                })
                .is_some()
        });
    if !has_oci_service {
        bail!(
            "--oci-pod requires an OCI app rootfs; \
             '{rootfs_name}' does not contain an sdme-oci-*.service unit"
        );
    }

    Ok(())
}

/// Validate `--oci-pod` constraints for kube commands.
///
/// Simplified version of `validate_oci_pod_args` for kube: skips the rootfs
/// OCI service check since kube always creates OCI services during build.
/// Only checks that the pod exists.
fn validate_kube_oci_pod_args(datadir: &std::path::Path, oci_pod: Option<&str>) -> Result<()> {
    let pod_name = match oci_pod {
        Some(n) => n,
        None => return Ok(()),
    };

    if !pod::exists(datadir, pod_name) {
        bail!("pod not found: {pod_name}");
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

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

                config::save_key(config_path, &toml_key, toml_val)?;
            }
            // Handled before root check above.
            ConfigCommand::AppArmorProfile => unreachable!(),
            ConfigCommand::Completions { .. } => unreachable!(),
        },
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
        } => {
            system_check::check_systemd_version(252)?;
            let limits = parse_limits(memory, cpus, cpu_weight)?;
            let (sec, hardened) = parse_security(security, &cfg)?;
            let mut network = parse_network(network)?;
            if hardened && !network.private_network {
                network.private_network = true;
            }
            validate_pod_args(&cfg.datadir, pod.as_deref(), sec.userns)?;
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

            // Store OCI_APP in state for exec --oci and logs --oci.
            if let Some(ref app_name) = oci_app_name {
                let state_path = cfg.datadir.join("state").join(&name);
                let mut state = sdme::State::read_from(&state_path)?;
                state.set("OCI_APP", app_name);
                state.write_to(&state_path)?;
            }

            eprintln!("creating '{name}'");
            if enable {
                systemd::enable(
                    &cfg.datadir,
                    &name,
                    cfg.tasks_max,
                    cfg.boot_timeout,
                    cli.verbose,
                )?;
                eprintln!("enabled '{name}' for auto-start on boot");
            }
            println!("{name}");
        }
        Command::Exec { name, oci, command } => {
            let name = containers::resolve_name(&cfg.datadir, &name)?;
            let status = if let Some(ref oci_app) = oci {
                let explicit = if oci_app.is_empty() {
                    None
                } else {
                    Some(oci_app.as_str())
                };
                let app_name = resolve_oci_app_name(&cfg.datadir, &name, explicit)?;
                containers::exec_oci(&cfg.datadir, &name, &app_name, &command, cli.verbose)?
            } else {
                containers::exec(
                    &cfg.datadir,
                    &name,
                    &command,
                    cfg.join_as_sudo_user,
                    cli.verbose,
                )?
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
            system_check::check_systemd_version(252)?;
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
            let config_boot_timeout = cfg.boot_timeout;
            for_each_container(datadir, &targets, "starting", "started", |name| {
                containers::ensure_exists(datadir, name)?;
                start_and_await_boot(
                    datadir,
                    name,
                    cfg.tasks_max,
                    boot_timeout,
                    config_boot_timeout,
                    verbose,
                )
            })?;
        }
        Command::Enable { names } => {
            let datadir = &cfg.datadir;
            let verbose = cli.verbose;
            for_each_container(datadir, &names, "enabling", "enabled", |name| {
                containers::ensure_exists(datadir, name)?;
                systemd::enable(datadir, name, cfg.tasks_max, cfg.boot_timeout, verbose)
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

                system_check::check_systemd_version(252)?;
                eprintln!("starting '{name}'");
                let boot_timeout =
                    std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
                start_and_await_boot(
                    &cfg.datadir,
                    &name,
                    cfg.tasks_max,
                    boot_timeout,
                    cfg.boot_timeout,
                    cli.verbose,
                )?;
            }

            if let Some(ref oci_app) = oci {
                let explicit = if oci_app.is_empty() {
                    None
                } else {
                    Some(oci_app.as_str())
                };
                let app_name = resolve_oci_app_name(&cfg.datadir, &name, explicit)?;
                let command = if command.is_empty() {
                    vec!["/bin/sh".to_string()]
                } else {
                    command
                };
                eprintln!("joining '{name}' (oci app '{app_name}')");
                let status =
                    containers::exec_oci(&cfg.datadir, &name, &app_name, &command, cli.verbose)?;
                std::process::exit(status.code().unwrap_or(1));
            }

            eprintln!("joining '{name}'");
            let status = containers::join(
                &cfg.datadir,
                &name,
                &command,
                cfg.join_as_sudo_user,
                cli.verbose,
            )?;
            std::process::exit(status.code().unwrap_or(1));
        }
        Command::Logs { name, oci, args } => {
            let name = containers::resolve_name(&cfg.datadir, &name)?;
            if let Some(ref oci_app) = oci {
                let explicit = if oci_app.is_empty() {
                    None
                } else {
                    Some(oci_app.as_str())
                };
                let app_name = resolve_oci_app_name(&cfg.datadir, &name, explicit)?;
                let mut command = vec![
                    "/usr/bin/journalctl".to_string(),
                    "-u".to_string(),
                    format!("sdme-oci-{app_name}.service"),
                ];
                command.extend(args);
                let status = containers::exec(
                    &cfg.datadir,
                    &name,
                    &command,
                    cfg.join_as_sudo_user,
                    cli.verbose,
                )?;
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
            system_check::check_systemd_version(252)?;
            let limits = parse_limits(memory, cpus, cpu_weight)?;
            let (sec, hardened) = parse_security(security, &cfg)?;
            let mut network = parse_network(network)?;
            if hardened && !network.private_network {
                network.private_network = true;
            }
            validate_pod_args(&cfg.datadir, pod.as_deref(), sec.userns)?;
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

            // Store OCI_APP in state for exec --oci and logs --oci.
            if let Some(ref app_name) = oci_app_name {
                let state_path = cfg.datadir.join("state").join(&name);
                let mut state = sdme::State::read_from(&state_path)?;
                state.set("OCI_APP", app_name);
                state.write_to(&state_path)?;
            }

            eprintln!("creating '{name}'");

            if enable {
                systemd::enable(
                    &cfg.datadir,
                    &name,
                    cfg.tasks_max,
                    cfg.boot_timeout,
                    cli.verbose,
                )?;
                eprintln!("enabled '{name}' for auto-start on boot");
            }

            // Warn about hardened/strict implications for interactive use.
            if hardened && is_host_rootfs {
                eprintln!("note: --private-network is active; the container has no internet");
                eprintln!("note: --no-new-privileges is active; sudo/su will not work inside");
            }

            eprintln!("starting '{name}'");
            let boot_result = (|| -> Result<()> {
                systemd::start(
                    &cfg.datadir,
                    &name,
                    cfg.tasks_max,
                    cfg.boot_timeout,
                    cli.verbose,
                )?;
                let boot_timeout =
                    std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
                systemd::await_boot(&name, boot_timeout, cli.verbose)?;
                Ok(())
            })();

            if let Err(e) = boot_result {
                sdme::reset_interrupt();
                eprintln!("boot failed, stopping '{name}'");
                let _ = containers::stop(
                    &name,
                    containers::StopMode::Terminate,
                    cfg.stop_timeout_terminate,
                    cli.verbose,
                );
                return Err(e);
            }

            eprintln!("joining '{name}'");
            let status = containers::join(
                &cfg.datadir,
                &name,
                &command,
                cfg.join_as_sudo_user,
                cli.verbose,
            )?;
            if !status.success() {
                let code = status.code().unwrap_or(1);
                eprintln!("join failed (exit code {code}), removing '{name}'");
                let _ = containers::remove(&cfg.datadir, &name, cli.verbose);
                std::process::exit(code);
            }
        }
        Command::Ps => {
            let entries = containers::list(&cfg.datadir)?;
            if entries.is_empty() {
                println!("no containers found");
            } else {
                let name_w = entries.iter().map(|e| e.name.len()).max().unwrap().max(4);
                let status_w = entries.iter().map(|e| e.status.len()).max().unwrap().max(6);
                let health_w = entries.iter().map(|e| e.health.len()).max().unwrap().max(6);
                let os_w = entries.iter().map(|e| e.os.len()).max().unwrap().max(2);
                let pod_w = if entries.iter().any(|e| !e.pod.is_empty()) {
                    Some(entries.iter().map(|e| e.pod.len()).max().unwrap().max(3))
                } else {
                    None
                };
                let oci_pod_w = if entries.iter().any(|e| !e.oci_pod.is_empty()) {
                    Some(
                        entries
                            .iter()
                            .map(|e| e.oci_pod.len())
                            .max()
                            .unwrap()
                            .max(7),
                    )
                } else {
                    None
                };
                let show_userns = entries.iter().any(|e| e.userns);
                let show_enabled = entries.iter().any(|e| e.enabled);
                let binds_display: Vec<String> =
                    entries.iter().map(|e| e.binds_display()).collect();
                let binds_w = if binds_display.iter().any(|b| !b.is_empty()) {
                    Some(binds_display.iter().map(|b| b.len()).max().unwrap().max(5))
                } else {
                    None
                };
                let kube_w = if entries.iter().any(|e| !e.kube.is_empty()) {
                    Some(entries.iter().map(|e| e.kube.len()).max().unwrap().max(4))
                } else {
                    None
                };
                // Header.
                print!(
                    "{:<name_w$}  {:<status_w$}  {:<health_w$}  {:<os_w$}",
                    "NAME", "STATUS", "HEALTH", "OS"
                );
                if let Some(pw) = pod_w {
                    print!("  {:<pw$}", "POD");
                }
                if let Some(pw) = oci_pod_w {
                    print!("  {:<pw$}", "OCI-POD");
                }
                if show_userns {
                    print!("  USERNS");
                }
                if show_enabled {
                    print!("  ENABLED");
                }
                if let Some(bw) = binds_w {
                    print!("  {:<bw$}", "BINDS");
                }
                if let Some(kw) = kube_w {
                    print!("  {:<kw$}", "KUBE");
                }
                println!();
                // Rows.
                for (i, e) in entries.iter().enumerate() {
                    print!(
                        "{:<name_w$}  {:<status_w$}  {:<health_w$}  {:<os_w$}",
                        e.name, e.status, e.health, e.os
                    );
                    if let Some(pw) = pod_w {
                        print!("  {:<pw$}", e.pod);
                    }
                    if let Some(pw) = oci_pod_w {
                        print!("  {:<pw$}", e.oci_pod);
                    }
                    if show_userns {
                        print!("  {:<6}", if e.userns { "yes" } else { "" });
                    }
                    if show_enabled {
                        print!("  {:<7}", if e.enabled { "yes" } else { "" });
                    }
                    if let Some(bw) = binds_w {
                        print!("  {:<bw$}", binds_display[i]);
                    }
                    if let Some(kw) = kube_w {
                        print!("  {:<kw$}", e.kube);
                    }
                    println!();
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
                    .filter(|e| e.status == "running")
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
        Command::Pod(cmd) => match cmd {
            PodCommand::New { name } => {
                pod::create(&cfg.datadir, &name, cli.verbose)?;
                eprintln!("created pod '{name}'");
                println!("{name}");
            }
            PodCommand::Ls => {
                let pods = pod::list(&cfg.datadir)?;
                if pods.is_empty() {
                    println!("no pods found");
                } else {
                    let name_w = pods.iter().map(|p| p.name.len()).max().unwrap().max(4);
                    println!("{:<name_w$}  ACTIVE  CREATED", "NAME");
                    for p in &pods {
                        let active = if p.active { "yes" } else { "no" };
                        println!("{:<name_w$}  {:<6}  {}", p.name, active, p.created);
                    }
                }
            }
            PodCommand::Rm { names, force } => {
                let mut failed = false;
                for name in &names {
                    check_interrupted()?;
                    eprintln!("removing pod '{name}'");
                    if let Err(e) = pod::remove(&cfg.datadir, name, force, cli.verbose) {
                        eprintln!("error: {name}: {e}");
                        failed = true;
                    } else {
                        println!("{name}");
                    }
                }
                if failed {
                    bail!("some pods could not be removed");
                }
            }
        },
        Command::Kube(cmd) => match cmd {
            KubeCommand::Apply {
                file,
                base_fs,
                timeout,
                pod,
                oci_pod,
                security: security_args,
                masked_services,
            } => {
                system_check::check_systemd_version(252)?;
                let (sec, hardened) = parse_security(security_args, &cfg)?;
                validate_pod_args(&cfg.datadir, pod.as_deref(), sec.userns)?;
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
                // Kube containers always use an imported rootfs (never host),
                // so network_zone is not applicable (kube doesn't expose it).
                // Resolve masked services with a default NetworkConfig.
                let masked_services =
                    resolve_masked_services(masked_services, &NetworkConfig::default(), &cfg)?;
                let docker_creds = docker_credentials(&cfg);
                let docker_creds_ref = docker_creds.as_ref().map(|(u, t)| (u.as_str(), t.as_str()));
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
                        http: &cfg.http_config()?,
                        auto_gc: cfg.auto_fs_gc,
                        security: sec,
                        hardened,
                        masked_services,
                    },
                )?;
                eprintln!("starting '{name}'");
                let boot_result = (|| -> Result<()> {
                    systemd::start(
                        &cfg.datadir,
                        &name,
                        cfg.tasks_max,
                        cfg.boot_timeout,
                        cli.verbose,
                    )?;
                    let boot_timeout =
                        std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
                    systemd::await_boot(&name, boot_timeout, cli.verbose)?;
                    Ok(())
                })();
                if let Err(e) = boot_result {
                    sdme::reset_interrupt();
                    eprintln!("boot failed, stopping '{name}'");
                    let _ = containers::stop(
                        &name,
                        containers::StopMode::Terminate,
                        cfg.stop_timeout_terminate,
                        cli.verbose,
                    );
                    return Err(e);
                }
                eprintln!("joining '{name}'");
                let status =
                    containers::join(&cfg.datadir, &name, &[], cfg.join_as_sudo_user, cli.verbose)?;
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
                security: security_args,
                masked_services,
            } => {
                system_check::check_systemd_version(252)?;
                let (sec, hardened) = parse_security(security_args, &cfg)?;
                validate_pod_args(&cfg.datadir, pod.as_deref(), sec.userns)?;
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
                let masked_services =
                    resolve_masked_services(masked_services, &NetworkConfig::default(), &cfg)?;
                let docker_creds = docker_credentials(&cfg);
                let docker_creds_ref = docker_creds.as_ref().map(|(u, t)| (u.as_str(), t.as_str()));
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
                        http: &cfg.http_config()?,
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
            } => {
                system_check::check_systemd_version(252)?;
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
                        http: cfg.http_config()?,
                        auto_gc: cfg.auto_fs_gc,
                        distros: &cfg.distros,
                    },
                )?;
                println!("{name}");
            }
            RootfsCommand::Ls => {
                let entries = rootfs::list(&cfg.datadir)?;
                if entries.is_empty() {
                    println!("no root filesystems found");
                } else {
                    let name_w = entries.iter().map(|e| e.name.len()).max().unwrap().max(4);
                    let distro_w = entries.iter().map(|e| e.distro.len()).max().unwrap().max(6);
                    println!("{:<name_w$}  {:<distro_w$}  PATH", "NAME", "DISTRO");
                    for entry in &entries {
                        let path = cfg.datadir.join("fs").join(&entry.name);
                        println!(
                            "{:<name_w$}  {:<distro_w$}  {}",
                            entry.name,
                            entry.distro,
                            path.display()
                        );
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
                    if let Err(e) = rootfs::remove(&cfg.datadir, name, cfg.auto_fs_gc, cli.verbose)
                    {
                        eprintln!("error: {name}: {e}");
                        failed = true;
                    } else {
                        println!("{name}");
                    }
                }
                if failed {
                    bail!("some fs entries could not be removed");
                }
            }
            RootfsCommand::Build {
                name,
                config,
                timeout,
                force,
            } => {
                system_check::check_systemd_version(252)?;
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
                        verbose: cli.verbose,
                    },
                )?;
                println!("{name}");
            }
            RootfsCommand::Export {
                name,
                output,
                container,
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
                let result = if container {
                    export::export_container(&cfg.datadir, &name, &output_path, &export_opts)?
                } else {
                    export::export_rootfs(&cfg.datadir, &name, &output_path, &export_opts)?
                };
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
    }

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
