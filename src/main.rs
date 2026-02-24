use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use sdme::import::InstallPackages;
use sdme::{NetworkConfig, ResourceLimits, config, containers, rootfs, system_check, systemd};

#[derive(Parser)]
#[command(name = "sdme", about = "Lightweight systemd-nspawn containers with overlayfs")]
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

        #[command(flatten)]
        network: NetworkArgs,
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

        #[command(flatten)]
        network: NetworkArgs,

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
}

#[derive(Subcommand)]
enum RootfsCommand {
    /// Import a root filesystem from a directory, tarball, URL, OCI image, or QCOW2 disk image
    Import {
        /// Name for the imported rootfs
        name: String,
        /// Source: directory path, tarball (.tar, .tar.gz, .tar.bz2, .tar.xz, .tar.zst), URL, OCI image (.oci.tar.xz, etc.), or QCOW2 disk image
        source: String,
        /// Remove leftover staging directory from a previous failed import
        #[arg(short, long)]
        force: bool,
        /// Whether to install systemd packages if missing (auto: prompt if interactive)
        #[arg(long, value_enum, default_value_t = InstallPackages::Auto)]
        install_packages: InstallPackages,
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

fn main() -> Result<()> {
    let cli = Cli::parse();

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
                        let secs: u64 = value.parse()
                            .map_err(|_| anyhow::anyhow!("boot_timeout must be a positive integer (seconds)"))?;
                        if secs == 0 {
                            bail!("boot_timeout must be greater than 0");
                        }
                        cfg.boot_timeout = secs;
                    }
                    "join_as_sudo_user" => match value.as_str() {
                        "yes" => cfg.join_as_sudo_user = true,
                        "no" => cfg.join_as_sudo_user = false,
                        _ => bail!("invalid value for join_as_sudo_user: {value} (expected yes or no)"),
                    },
                    _ => bail!("unknown config key: {key}"),
                }
                config::save(&cfg, config_path)?;
            }
        },
        Command::Create { name, fs, memory, cpus, cpu_weight, network } => {
            system_check::check_systemd_version(252)?;
            let limits = parse_limits(memory, cpus, cpu_weight)?;
            let network = parse_network(network)?;
            let opts = containers::CreateOptions { name, rootfs: fs, limits, network };
            let name = containers::create(&cfg.datadir, &opts, cli.verbose)?;
            eprintln!("creating '{name}'");
            println!("{name}");
        }
        Command::Exec { name, command } => {
            let name = containers::resolve_name(&cfg.datadir, &name)?;
            containers::exec(&cfg.datadir, &name, &command, cfg.join_as_sudo_user, cli.verbose)?;
        }
        Command::Set { name, memory, cpus, cpu_weight } => {
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
            containers::join(&cfg.datadir, &name, &command, cfg.join_as_sudo_user, cli.verbose)?;
        }
        Command::Logs { name, args } => {
            system_check::check_dependencies(&[
                ("journalctl", "apt install systemd"),
            ], cli.verbose)?;
            let name = containers::resolve_name(&cfg.datadir, &name)?;
            let unit = systemd::service_name(&name);
            let mut cmd = std::process::Command::new("journalctl");
            cmd.args(["-u", &unit]);
            cmd.args(&args);
            if cli.verbose {
                eprintln!("exec: journalctl {}",
                    cmd.get_args()
                        .map(|a| a.to_string_lossy())
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
            let err = cmd.exec();
            bail!("failed to exec journalctl: {err}");
        }
        Command::New { name, fs, timeout, memory, cpus, cpu_weight, network, command } => {
            system_check::check_systemd_version(252)?;
            let limits = parse_limits(memory, cpus, cpu_weight)?;
            let network = parse_network(network)?;
            let opts = containers::CreateOptions { name, rootfs: fs, limits, network };
            let name = containers::create(&cfg.datadir, &opts, cli.verbose)?;
            eprintln!("creating '{name}'");

            eprintln!("starting '{name}'");
            let boot_result = (|| -> Result<()> {
                systemd::start(&cfg.datadir, &name, cli.verbose)?;
                let boot_timeout = std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
                await_boot(&name, boot_timeout, cli.verbose)?;
                Ok(())
            })();

            if let Err(e) = boot_result {
                eprintln!("boot failed, removing '{name}'");
                let _ = containers::remove(&cfg.datadir, &name, cli.verbose);
                return Err(e);
            }

            eprintln!("joining '{name}'");
            containers::join(&cfg.datadir, &name, &command, cfg.join_as_sudo_user, cli.verbose)?;
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
                        e.name, e.status, e.health, e.os, e.shared.display()
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
                        eprint!("are you sure? [y/N] ");
                        let mut answer = String::new();
                        std::io::stdin().read_line(&mut answer)?;
                        if !answer.trim().eq_ignore_ascii_case("y") {
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
        Command::Fs(cmd) => match cmd {
            RootfsCommand::Import { source, name, force, install_packages } => {
                system_check::check_systemd_version(252)?;
                rootfs::import(&cfg.datadir, &source, &name, cli.verbose, force, install_packages)?;
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
                        println!("{:<name_w$}  {:<distro_w$}  {}", entry.name, entry.distro, path.display());
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
                            eprint!("are you sure? [y/N] ");
                            let mut answer = String::new();
                            std::io::stdin().read_line(&mut answer)?;
                            if !answer.trim().eq_ignore_ascii_case("y") {
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
            RootfsCommand::Build { name, config, timeout, force } => {
                system_check::check_systemd_version(252)?;
                let boot_timeout = timeout.unwrap_or(cfg.boot_timeout);
                sdme::build::build(&cfg.datadir, &name, &config, boot_timeout, force, cli.verbose)?;
                println!("{name}");
            }
        },
    }

    Ok(())
}
