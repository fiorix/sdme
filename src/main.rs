use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use sdme::import::InstallPackages;
use sdme::{config, containers, rootfs, system_check, systemd, validate_name};

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

#[derive(Subcommand)]
enum Command {
    /// Manage configuration
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Create a new container
    Create {
        /// Container name (generated if not provided)
        #[arg(short, long)]
        name: Option<String>,

        /// Root filesystem to use (host filesystem if not provided)
        #[arg(short = 'r', long = "fs")]
        fs: Option<String>,
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
        #[arg(short, long)]
        name: Option<String>,

        /// Root filesystem to use (host filesystem if not provided)
        #[arg(short = 'r', long = "fs")]
        fs: Option<String>,

        /// Boot timeout in seconds (overrides config, default: 60)
        #[arg(short, long)]
        timeout: Option<u64>,

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
    },

    /// Stop one or more running containers
    Stop {
        /// Container names
        names: Vec<String>,
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
    /// Import a root filesystem from a directory, tarball, URL, or QCOW2 image
    Import {
        /// Source: directory path, tarball file (.tar, .tar.gz, .tar.bz2, .tar.xz), URL, or QCOW2 image
        source: String,
        /// Name for the imported rootfs
        #[arg(short, long)]
        name: String,
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

fn main() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("sdme requires root privileges; run with sudo");
    }

    let cli = Cli::parse();

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
        Command::Create { name, fs } => {
            system_check::check_systemd_version(257)?;
            let opts = containers::CreateOptions { name, rootfs: fs };
            let name = containers::create(&cfg.datadir, &opts, cli.verbose)?;
            eprintln!("creating '{name}'");
            println!("{name}");
        }
        Command::Exec { name, command } => {
            validate_name(&name)?;
            containers::exec(&cfg.datadir, &name, &command, cfg.join_as_sudo_user, cli.verbose)?;
        }
        Command::Start { name, timeout } => {
            system_check::check_systemd_version(257)?;
            validate_name(&name)?;
            containers::ensure_exists(&cfg.datadir, &name)?;
            eprintln!("starting '{name}'");
            systemd::start(&cfg.datadir, &name, cli.verbose)?;
            let boot_timeout = std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
            let boot_start = std::time::Instant::now();
            systemd::wait_for_boot(&name, boot_timeout, cli.verbose)?;
            let remaining = boot_timeout.saturating_sub(boot_start.elapsed());
            systemd::wait_for_dbus(&name, remaining, cli.verbose)?;
        }
        Command::Join { name, command } => {
            validate_name(&name)?;
            eprintln!("joining '{name}'");
            containers::join(&cfg.datadir, &name, &command, cfg.join_as_sudo_user, cli.verbose)?;
        }
        Command::Logs { name, args } => {
            system_check::check_dependencies(&[
                ("journalctl", "apt install systemd"),
            ], cli.verbose)?;
            validate_name(&name)?;
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
        Command::New { name, fs, timeout, command } => {
            system_check::check_systemd_version(257)?;
            let opts = containers::CreateOptions { name, rootfs: fs };
            let name = containers::create(&cfg.datadir, &opts, cli.verbose)?;
            eprintln!("creating '{name}'");

            eprintln!("starting '{name}'");
            systemd::start(&cfg.datadir, &name, cli.verbose)?;

            let boot_timeout = std::time::Duration::from_secs(timeout.unwrap_or(cfg.boot_timeout));
            let boot_start = std::time::Instant::now();
            systemd::wait_for_boot(&name, boot_timeout, cli.verbose)?;
            let remaining = boot_timeout.saturating_sub(boot_start.elapsed());
            systemd::wait_for_dbus(&name, remaining, cli.verbose)?;
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
        Command::Rm { names } => {
            let mut failed = false;
            for name in &names {
                if let Err(e) = validate_name(name) {
                    eprintln!("error: {name}: {e}");
                    failed = true;
                    continue;
                }
                eprintln!("removing '{name}'");
                if let Err(e) = containers::remove(&cfg.datadir, name, cli.verbose) {
                    eprintln!("error: {name}: {e}");
                    failed = true;
                } else {
                    println!("{name}");
                }
            }
            if failed {
                bail!("some containers could not be removed");
            }
        }
        Command::Stop { names } => {
            let mut failed = false;
            for name in &names {
                if let Err(e) = validate_name(name) {
                    eprintln!("error: {name}: {e}");
                    failed = true;
                    continue;
                }
                if let Err(e) = containers::ensure_exists(&cfg.datadir, name) {
                    eprintln!("error: {name}: {e}");
                    failed = true;
                    continue;
                }
                eprintln!("stopping '{name}'");
                if let Err(e) = containers::stop(name, cli.verbose) {
                    eprintln!("error: {name}: {e}");
                    failed = true;
                } else {
                    println!("{name}");
                }
            }
            if failed {
                bail!("some containers could not be stopped");
            }
        }
        Command::Fs(cmd) => match cmd {
            RootfsCommand::Import { source, name, force, install_packages } => {
                system_check::check_systemd_version(257)?;
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
            RootfsCommand::Rm { names } => {
                let mut failed = false;
                for name in &names {
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
        },
    }

    Ok(())
}
