//! sdme-kube-probe: purpose-built health check binary for Kubernetes probes.
//!
//! Runs probe checks (exec, HTTP, TCP, gRPC) with failure counting and
//! automatic actions (service restart, readiness state). Designed to be
//! embedded into sdme and deployed at `/oci/.sdme-kube-probe` inside the
//! container rootfs.

mod exec;
#[cfg(feature = "probe")]
mod grpc;
mod http;
mod runner;
mod tcp;

use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "sdme-kube-probe", version)]
struct Cli {
    /// Enable verbose output.
    #[arg(short, long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a probe check with failure tracking.
    Run(RunArgs),
}

#[derive(Args)]
struct RunArgs {
    /// Probe type.
    #[arg(long = "type")]
    probe_type: ProbeType,
    /// App name.
    #[arg(long)]
    name: String,
    /// Failure threshold before action.
    #[arg(long)]
    threshold: u32,
    /// Systemd service to restart on threshold (startup/liveness).
    #[arg(long)]
    service: String,
    /// Check to execute.
    #[command(subcommand)]
    check: Check,
}

#[derive(Clone, ValueEnum)]
pub(crate) enum ProbeType {
    Startup,
    Liveness,
    Readiness,
}

impl std::fmt::Display for ProbeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ProbeType::Startup => "startup",
            ProbeType::Liveness => "liveness",
            ProbeType::Readiness => "readiness",
        })
    }
}

#[derive(Subcommand)]
enum Check {
    /// Execute a command inside the app root via chroot.
    Exec(ExecArgs),
    /// Send an HTTP GET request.
    Http(HttpArgs),
    /// Check TCP port connectivity.
    Tcp(TcpArgs),
    /// Send a gRPC health check request.
    #[cfg(feature = "probe")]
    Grpc(GrpcArgs),
}

#[derive(Args)]
struct ExecArgs {
    /// App root filesystem path.
    #[arg(long)]
    app_root: String,
    /// Timeout in seconds.
    #[arg(long, default_value_t = 1)]
    timeout: u32,
    /// Command and arguments to execute.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Args)]
struct HttpArgs {
    /// Port to connect to.
    #[arg(long)]
    port: u16,
    /// HTTP path.
    #[arg(long, default_value = "/")]
    path: String,
    /// URL scheme (http or https).
    #[arg(long, default_value = "http")]
    scheme: String,
    /// Custom HTTP headers (format: "Name: Value"), repeatable.
    #[arg(long)]
    header: Vec<String>,
    /// Timeout in seconds.
    #[arg(long, default_value_t = 1)]
    timeout: u32,
}

#[derive(Args)]
struct TcpArgs {
    /// Port to connect to.
    #[arg(long)]
    port: u16,
    /// Timeout in seconds.
    #[arg(long, default_value_t = 1)]
    timeout: u32,
}

#[cfg(feature = "probe")]
#[derive(Args)]
struct GrpcArgs {
    /// Port to connect to.
    #[arg(long)]
    port: u16,
    /// gRPC service name (empty = overall server health).
    #[arg(long)]
    service: Option<String>,
    /// Timeout in seconds.
    #[arg(long, default_value_t = 1)]
    timeout: u32,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let verbose = cli.verbose;
    match cli.command {
        Command::Run(args) => {
            // Startup probe: once done, skip the check entirely.
            if matches!(args.probe_type, ProbeType::Startup) {
                let done_file = format!("/run/sdme-probe-startup-{}.done", args.name);
                if std::path::Path::new(&done_file).exists() {
                    if verbose {
                        eprintln!(
                            "probe {}/{}: already done, skipping",
                            args.probe_type, args.name
                        );
                    }
                    return ExitCode::SUCCESS;
                }
            }

            let check_desc = match &args.check {
                Check::Exec(a) => format!("exec {:?}", a.command),
                Check::Http(a) => {
                    let hdr = if a.header.is_empty() {
                        String::new()
                    } else {
                        format!(" (+{} headers)", a.header.len())
                    };
                    format!("{}://127.0.0.1:{}{}{hdr}", a.scheme, a.port, a.path)
                }
                Check::Tcp(a) => format!("tcp 127.0.0.1:{}", a.port),
                #[cfg(feature = "probe")]
                Check::Grpc(a) => format!(
                    "grpc 127.0.0.1:{}{}",
                    a.port,
                    a.service
                        .as_deref()
                        .map(|s| format!("/{s}"))
                        .unwrap_or_default()
                ),
            };

            let success = match &args.check {
                Check::Exec(a) => exec::check(&a.app_root, a.timeout, &a.command),
                Check::Http(a) => http::check(a.port, &a.path, &a.scheme, &a.header, a.timeout),
                Check::Tcp(a) => tcp::check(a.port, a.timeout),
                #[cfg(feature = "probe")]
                Check::Grpc(a) => grpc::check(a.port, a.service.as_deref(), a.timeout),
            };

            if verbose {
                eprintln!(
                    "probe {}/{}: {} -> {}",
                    args.probe_type,
                    args.name,
                    check_desc,
                    if success { "ok" } else { "fail" }
                );
            }

            runner::handle_result(
                &args.probe_type,
                &args.name,
                &args.service,
                args.threshold,
                success,
                verbose,
            )
        }
    }
}
