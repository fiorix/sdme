use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use sdme::import::{ImportOptions, InstallPackages, OciBase};
use sdme::{
    config, confirm, containers, rootfs, system_check, systemd, BindConfig, EnvConfig,
    NetworkConfig, ResourceLimits,
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

        #[command(flatten)]
        network: NetworkArgs,

        #[command(flatten)]
        mounts: MountArgs,
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

        #[command(flatten)]
        network: NetworkArgs,

        #[command(flatten)]
        mounts: MountArgs,

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

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum RootfsCommand {
    /// Import a root filesystem from a directory, tarball, URL, OCI image, registry image, or QCOW2 disk image
    #[command(after_long_help = "\
OCI REGISTRY IMAGES:
    When the source is an OCI registry image (e.g. docker.io/ubuntu:24.04),
    sdme pulls the image layers and extracts the root filesystem.

    --oci-base controls how the image is classified:

      auto (default)  Auto-detect from image config. Base OS images have no
                      entrypoint, a shell as default command, and no exposed
                      ports. Everything else is an application image.

      yes             Force base OS mode. The rootfs goes through systemd
                      detection and package installation (apt/dnf). Use this
                      for OS images that the heuristic misclassifies.

      no              Force application mode. Requires --oci-base-fs to
                      specify a systemd-capable rootfs as the base layer.
                      The OCI rootfs is placed under /oci/root and a systemd
                      unit is generated to run the application.

    Application images (--oci-base=no or auto-detected):
      The OCI rootfs is placed under /oci/root inside a copy of the base
      rootfs specified by --oci-base-fs. A systemd service unit is generated
      to run the entrypoint/cmd via RootDirectory=/oci/root. Exposed ports
      and volumes from the OCI config are saved under /oci/ for reference.

    Examples:
      sdme fs import ubuntu docker.io/ubuntu -v
      sdme fs import nginx docker.io/nginx --oci-base-fs=ubuntu -v
      sdme fs import myapp ghcr.io/org/app:v1 --oci-base=no --oci-base-fs=ubuntu")]
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
        #[arg(long, value_enum, default_value_t = OciBase::Auto)]
        oci_base: OciBase,
        /// Base rootfs for OCI application images (must have systemd; OCI rootfs goes under /oci/root)
        #[arg(long)]
        oci_base_fs: Option<String>,
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

fn await_boot(name: &str, timeout: std::time::Duration, verbose: bool) -> Result<()> {
    systemd::await_boot(name, timeout, verbose)
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle completions before root check (no privileges needed).
    if let Command::Completions { shell } = cli.command {
        clap_complete::generate(shell, &mut Cli::command(), "sdme", &mut std::io::stdout());
        return Ok(());
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
                    _ => bail!("unknown config key: {key}"),
                }
                config::save(&cfg, config_path)?;
            }
        },
        Command::Create {
            name,
            fs,
            memory,
            cpus,
            cpu_weight,
            opaque_dirs,
            network,
            mounts,
        } => {
            system_check::check_systemd_version(252)?;
            let limits = parse_limits(memory, cpus, cpu_weight)?;
            let network = parse_network(network)?;
            let (binds, envs) = parse_mounts(mounts)?;
            let opaque_dirs = resolve_opaque_dirs(opaque_dirs, fs.is_none(), &cfg);
            let opts = containers::CreateOptions {
                name,
                rootfs: fs,
                limits,
                network,
                opaque_dirs,
                binds,
                envs,
            };
            let name = containers::create(&cfg.datadir, &opts, cli.verbose)?;
            eprintln!("creating '{name}'");
            println!("{name}");
        }
        Command::Exec { name, command } => {
            let name = containers::resolve_name(&cfg.datadir, &name)?;
            containers::exec(
                &cfg.datadir,
                &name,
                &command,
                cfg.join_as_sudo_user,
                cli.verbose,
            )?;
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
            if let Err(e) = await_boot(&name, boot_timeout, cli.verbose) {
                eprintln!("boot failed, stopping '{name}'");
                let _ = containers::stop(&name, cli.verbose);
                return Err(e);
            }
        }
        Command::Join { name, command } => {
            let name = containers::resolve_name(&cfg.datadir, &name)?;
            eprintln!("joining '{name}'");
            containers::join(
                &cfg.datadir,
                &name,
                &command,
                cfg.join_as_sudo_user,
                cli.verbose,
            )?;
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
            network,
            mounts,
            command,
        } => {
            system_check::check_systemd_version(252)?;
            let limits = parse_limits(memory, cpus, cpu_weight)?;
            let network = parse_network(network)?;
            let (binds, envs) = parse_mounts(mounts)?;
            let opaque_dirs = resolve_opaque_dirs(opaque_dirs, fs.is_none(), &cfg);
            let opts = containers::CreateOptions {
                name,
                rootfs: fs,
                limits,
                network,
                opaque_dirs,
                binds,
                envs,
            };
            let name = containers::create(&cfg.datadir, &opts, cli.verbose)?;
            eprintln!("creating '{name}'");

            eprintln!("starting '{name}'");
            let boot_result = (|| -> Result<()> {
                systemd::start(&cfg.datadir, &name, cli.verbose)?;
                let boot_timeout =
                    std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
                await_boot(&name, boot_timeout, cli.verbose)?;
                Ok(())
            })();

            if let Err(e) = boot_result {
                eprintln!("boot failed, removing '{name}'");
                let _ = containers::remove(&cfg.datadir, &name, cli.verbose);
                return Err(e);
            }

            eprintln!("joining '{name}'");
            containers::join(
                &cfg.datadir,
                &name,
                &command,
                cfg.join_as_sudo_user,
                cli.verbose,
            )?;
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
                println!(
                    "{:<name_w$}  {:<status_w$}  {:<health_w$}  {:<os_w$}  SHARED",
                    "NAME", "STATUS", "HEALTH", "OS"
                );
                for e in &entries {
                    println!(
                        "{:<name_w$}  {:<status_w$}  {:<health_w$}  {:<os_w$}  {}",
                        e.name,
                        e.status,
                        e.health,
                        e.os,
                        e.shared.display()
                    );
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
                    if cli.verbose {
                        bail!("use -f to confirm removal in verbose (non-interactive) mode");
                    }
                    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 0 {
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
        Command::Stop { names, all } => {
            if all && !names.is_empty() {
                bail!("--all cannot be combined with container names");
            }
            if !all && names.is_empty() {
                bail!("provide one or more container names, or use --all");
            }
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
                containers::stop(name, verbose)
            })?;
        }
        // Handled before root check above.
        Command::Completions { .. } => unreachable!(),
        Command::Fs(cmd) => match cmd {
            RootfsCommand::Import {
                source,
                name,
                force,
                install_packages,
                oci_base,
                oci_base_fs,
            } => {
                system_check::check_systemd_version(252)?;
                if oci_base_fs.is_some() && oci_base == OciBase::Yes {
                    bail!("--oci-base-fs cannot be used with --oci-base=yes");
                }
                rootfs::import(
                    &cfg.datadir,
                    &ImportOptions {
                        source: &source,
                        name: &name,
                        verbose: cli.verbose,
                        force,
                        install_packages,
                        oci_base,
                        oci_base_fs: oci_base_fs.as_deref(),
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
                        if cli.verbose {
                            bail!("use -f to confirm removal in verbose (non-interactive) mode");
                        }
                        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 0 {
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
