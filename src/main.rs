use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use sdme::import::{ImportOptions, InstallPackages, OciMode};
use sdme::{
    config, confirm, containers, pod, rootfs, security, system_check, systemd, BindConfig,
    EnvConfig, NetworkConfig, ResourceLimits, SecurityConfig,
};

#[derive(Parser)]
#[command(
    name = "sdme",
    about = "Lightweight systemd-nspawn containers with overlayfs"
)]
struct Cli {
    /// Enable verbose output (implies non-interactive mode at runtime)
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Path to config file (default: ~/.config/sdme/sdmerc)
    #[arg(short, long, global = true)]
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

    /// Forward port HOST:CONTAINER[/PROTO] (implies --private-network, repeatable)
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
    /// profile to be loaded (see: sdme apparmor-profile --help)
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

        /// CPU weight 1–10000 (default: 100)
        #[arg(long)]
        cpu_weight: Option<String>,

        /// Make directories opaque in overlayfs (hides lower layer contents, repeatable)
        #[arg(short = 'o', long = "overlayfs-opaque-dirs")]
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
    },

    /// Run a command in a running container
    Exec {
        /// Container name
        name: String,
        /// Command to run inside the container
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },

    /// Enter a running container
    Join {
        /// Container name
        name: String,
        /// Command to run inside the container (default: login shell)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Show container logs (journalctl)
    Logs {
        /// Container name
        name: String,
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

        /// CPU weight 1–10000 (default: 100)
        #[arg(long)]
        cpu_weight: Option<String>,

        /// Make directories opaque in overlayfs (hides lower layer contents, repeatable)
        #[arg(short = 'o', long = "overlayfs-opaque-dirs")]
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

        /// Command to run inside the container (default: login shell)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// List containers
    Ps,

    /// Remove one or more containers
    Rm {
        /// Container names
        names: Vec<String>,

        /// Remove all containers
        #[arg(short, long)]
        all: bool,

        /// Skip confirmation prompts
        #[arg(short, long)]
        force: bool,
    },

    /// Stop one or more running containers
    Stop {
        /// Container names
        names: Vec<String>,

        /// Stop all running containers
        #[arg(short, long)]
        all: bool,

        /// Terminate (SIGTERM to nspawn leader, 30s timeout)
        #[arg(long, conflicts_with = "kill")]
        term: bool,

        /// Force-kill all processes (SIGKILL, 15s timeout)
        #[arg(long, conflicts_with = "term")]
        kill: bool,
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

        /// CPU weight 1–10000 (default: 100)
        #[arg(long)]
        cpu_weight: Option<String>,
    },

    /// Start a container
    Start {
        /// Container name
        name: String,

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
}

#[derive(Subcommand)]
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
                      The OCI rootfs is placed under /oci/root and a systemd
                      unit is generated to run the application.

    Examples:
      sdme fs import ubuntu docker.io/ubuntu -v
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
        /// Base rootfs for OCI application images (must have systemd; OCI rootfs goes under /oci/root)
        #[arg(long)]
        base_fs: Option<String>,
    },
    /// List imported root filesystems
    Ls,
    /// Remove one or more imported root filesystems
    Rm {
        /// Names of the rootfs entries to remove
        names: Vec<String>,

        /// Remove all imported root filesystems
        #[arg(short, long)]
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
        names: Vec<String>,
        /// Force removal even if containers reference the pod
        #[arg(short, long)]
        force: bool,
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

/// Validate `--pod` constraints before creating a container.
///
/// Checks that:
/// - The pod exists in the catalogue
/// - `--pod` is not combined with user namespace isolation (`--userns`,
///   `--hardened`). The kernel blocks `setns(CLONE_NEWNET)` from a child
///   user namespace into the pod's netns (owned by the init userns).
///   Use `--oci-pod` instead — its inner systemd drop-in joins the pod
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
/// - The rootfs is an OCI app rootfs (contains `sdme-oci-app.service`)
fn validate_oci_pod_args(
    datadir: &std::path::Path,
    oci_pod: Option<&str>,
    rootfs: Option<&str>,
) -> Result<()> {
    let pod_name = match oci_pod {
        Some(n) => n,
        None => return Ok(()),
    };

    if !pod::exists(datadir, pod_name) {
        bail!("pod not found: {pod_name}");
    }

    // Validate that the rootfs is an OCI app rootfs.
    let rootfs_name = match rootfs {
        Some(name) => name,
        None => bail!("--oci-pod requires an OCI app rootfs (use -r/--fs)"),
    };
    let rootfs_path = datadir.join("fs").join(rootfs_name);
    let service_path = rootfs_path.join("etc/systemd/system/sdme-oci-app.service");
    if !service_path.exists() {
        bail!(
            "--oci-pod requires an OCI app rootfs; \
             '{rootfs_name}' does not contain sdme-oci-app.service"
        );
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
        let resolved = config::resolve_path(config_path)?;
        eprintln!("config: {}", resolved.display());
    }

    let cfg = config::load(config_path)?;

    let interactive =
        cfg.interactive && !cli.verbose && unsafe { libc::isatty(libc::STDIN_FILENO) != 0 };

    match cli.command {
        Command::Config(cmd) => match cmd {
            ConfigCommand::Get => {
                cfg.display();
            }
            ConfigCommand::Set { key, value } => {
                let mut cfg = cfg;
                match key.as_str() {
                    "interactive" => match value.as_str() {
                        "yes" => cfg.interactive = true,
                        "no" => cfg.interactive = false,
                        _ => bail!("invalid value for interactive: {value} (expected yes or no)"),
                    },
                    "datadir" => {
                        let path = PathBuf::from(&value);
                        if !path.is_absolute() {
                            bail!("datadir must be an absolute path: {value}");
                        }
                        cfg.datadir = path;
                    }
                    "boot_timeout" => {
                        let secs: u64 = value.parse().map_err(|_| {
                            anyhow::anyhow!("boot_timeout must be a positive integer (seconds)")
                        })?;
                        if secs == 0 {
                            bail!("boot_timeout must be greater than 0");
                        }
                        cfg.boot_timeout = secs;
                    }
                    "join_as_sudo_user" => match value.as_str() {
                        "yes" => cfg.join_as_sudo_user = true,
                        "no" => cfg.join_as_sudo_user = false,
                        _ => bail!(
                            "invalid value for join_as_sudo_user: {value} (expected yes or no)"
                        ),
                    },
                    "host_rootfs_opaque_dirs" => {
                        if value.is_empty() {
                            cfg.host_rootfs_opaque_dirs = String::new();
                        } else {
                            let dirs = parse_opaque_dirs_config(&value);
                            let normalized = containers::validate_opaque_dirs(&dirs)?;
                            cfg.host_rootfs_opaque_dirs = normalized.join(",");
                        }
                    }
                    "hardened_drop_caps" => {
                        if value.is_empty() {
                            cfg.hardened_drop_caps = String::new();
                        } else {
                            let caps: Vec<String> = value
                                .split(',')
                                .map(|c| security::normalize_cap(c.trim()))
                                .collect();
                            for cap in &caps {
                                security::validate_capability(cap)?;
                            }
                            cfg.hardened_drop_caps = caps.join(",");
                        }
                    }
                    "default_base_fs" => {
                        if !value.is_empty() {
                            sdme::validate_name(&value)?;
                        }
                        cfg.default_base_fs = value;
                    }
                    _ => bail!("unknown config key: {key}"),
                }
                config::save(&cfg, config_path)?;
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
        } => {
            system_check::check_systemd_version(252)?;
            let limits = parse_limits(memory, cpus, cpu_weight)?;
            let (sec, hardened) = parse_security(security, &cfg)?;
            let mut network = parse_network(network)?;
            if hardened && !network.private_network {
                network.private_network = true;
            }
            validate_pod_args(&cfg.datadir, pod.as_deref(), sec.userns)?;
            validate_oci_pod_args(&cfg.datadir, oci_pod.as_deref(), fs.as_deref())?;
            let (binds, envs) = parse_mounts(mounts)?;
            let opaque_dirs = resolve_opaque_dirs(opaque_dirs, fs.is_none(), &cfg);
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
            };
            let name = containers::create(&cfg.datadir, &opts, cli.verbose)?;
            eprintln!("creating '{name}'");
            println!("{name}");
        }
        Command::Exec { name, command } => {
            let name = containers::resolve_name(&cfg.datadir, &name)?;
            let status = containers::exec(
                &cfg.datadir,
                &name,
                &command,
                cfg.join_as_sudo_user,
                cli.verbose,
            )?;
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
        Command::Start { name, timeout } => {
            system_check::check_systemd_version(252)?;
            let name = containers::resolve_name(&cfg.datadir, &name)?;
            containers::ensure_exists(&cfg.datadir, &name)?;
            eprintln!("starting '{name}'");
            systemd::start(&cfg.datadir, &name, cli.verbose)?;
            let boot_timeout = std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
            if let Err(e) = systemd::await_boot(&name, boot_timeout, cli.verbose) {
                sdme::reset_interrupt();
                eprintln!("boot failed, stopping '{name}'");
                let _ = containers::stop(&name, containers::StopMode::Terminate, cli.verbose);
                return Err(e);
            }
        }
        Command::Join { name, command } => {
            let name = containers::resolve_name(&cfg.datadir, &name)?;
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
        Command::Logs { name, args } => {
            system_check::check_dependencies(
                &[("journalctl", "apt install systemd")],
                cli.verbose,
            )?;
            let name = containers::resolve_name(&cfg.datadir, &name)?;
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
            validate_oci_pod_args(&cfg.datadir, oci_pod.as_deref(), fs.as_deref())?;
            let (binds, envs) = parse_mounts(mounts)?;
            let opaque_dirs = resolve_opaque_dirs(opaque_dirs, fs.is_none(), &cfg);
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
            };
            let is_host_rootfs = opts.rootfs.is_none();
            let name = containers::create(&cfg.datadir, &opts, cli.verbose)?;
            eprintln!("creating '{name}'");

            // Warn about hardened/strict implications for interactive use.
            if hardened && is_host_rootfs {
                eprintln!("note: --private-network is active; the container has no internet");
                eprintln!("note: --no-new-privileges is active; sudo/su will not work inside");
            }

            eprintln!("starting '{name}'");
            let boot_result = (|| -> Result<()> {
                systemd::start(&cfg.datadir, &name, cli.verbose)?;
                let boot_timeout =
                    std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
                systemd::await_boot(&name, boot_timeout, cli.verbose)?;
                Ok(())
            })();

            if let Err(e) = boot_result {
                sdme::reset_interrupt();
                eprintln!("boot failed, removing '{name}'");
                let _ = containers::remove(&cfg.datadir, &name, cli.verbose);
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
                let binds_display: Vec<String> =
                    entries.iter().map(|e| e.binds_display()).collect();
                let binds_w = if binds_display.iter().any(|b| !b.is_empty()) {
                    Some(binds_display.iter().map(|b| b.len()).max().unwrap().max(5))
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
                if let Some(bw) = binds_w {
                    print!("  {:<bw$}", "BINDS");
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
                    if let Some(bw) = binds_w {
                        print!("  {:<bw$}", binds_display[i]);
                    }
                    println!();
                }
            }
        }
        Command::Rm { names, all, force } => {
            if all && !names.is_empty() {
                bail!("--all cannot be combined with container names");
            }
            if !all && names.is_empty() {
                bail!("provide one or more container names, or use --all");
            }
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
            if all && !names.is_empty() {
                bail!("--all cannot be combined with container names");
            }
            if !all && names.is_empty() {
                bail!("provide one or more container names, or use --all");
            }
            let mode = if kill {
                containers::StopMode::Kill
            } else if term {
                containers::StopMode::Terminate
            } else {
                containers::StopMode::Graceful
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
                containers::stop(name, mode, verbose)
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
                if names.is_empty() {
                    bail!("provide one or more pod names");
                }
                let mut failed = false;
                for name in &names {
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
                if all && !names.is_empty() {
                    bail!("--all cannot be combined with fs names");
                }
                if !all && names.is_empty() {
                    bail!("provide one or more fs names, or use --all");
                }
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
                    if let Err(e) = rootfs::remove(&cfg.datadir, name, cli.verbose) {
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
                    &name,
                    &config,
                    boot_timeout,
                    force,
                    cli.verbose,
                )?;
                println!("{name}");
            }
        },
    }

    Ok(())
}
