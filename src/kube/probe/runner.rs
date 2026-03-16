//! Probe result handling: failure counting and actions.

use std::fs;
use std::process::{Command, ExitCode};

use super::ProbeType;

/// Handle the result of a probe check.
///
/// On success: reset fail counter, write state files.
/// On failure: increment counter, take action on threshold.
pub fn handle_result(
    probe_type: &ProbeType,
    name: &str,
    service: &str,
    threshold: u32,
    success: bool,
    verbose: bool,
) -> ExitCode {
    let fail_file = format!("/run/sdme-probe-{probe_type}-{name}.fail");

    if success {
        let _ = fs::remove_file(&fail_file);

        match probe_type {
            ProbeType::Startup => {
                let done_file = format!("/run/sdme-probe-startup-{name}.done");
                if let Err(e) = fs::write(&done_file, "done") {
                    eprintln!("probe {probe_type}/{name}: failed to write {done_file}: {e}");
                } else if verbose {
                    eprintln!("probe {probe_type}/{name}: wrote {done_file}");
                }
            }
            ProbeType::Readiness => {
                let ready_file = format!("/oci/apps/{name}/probe-ready");
                if let Err(e) = fs::write(&ready_file, "ready") {
                    eprintln!("probe {probe_type}/{name}: failed to write {ready_file}: {e}");
                } else if verbose {
                    eprintln!("probe {probe_type}/{name}: ready");
                }
            }
            ProbeType::Liveness => {
                if verbose {
                    eprintln!("probe {probe_type}/{name}: ok");
                }
            }
        }

        ExitCode::SUCCESS
    } else {
        let count = read_fail_count(&fail_file) + 1;
        let _ = fs::write(&fail_file, count.to_string());

        if verbose {
            eprintln!("probe {probe_type}/{name}: fail {count}/{threshold}");
        }

        if count >= threshold {
            let _ = fs::remove_file(&fail_file);

            match probe_type {
                ProbeType::Startup | ProbeType::Liveness => {
                    if verbose {
                        eprintln!(
                            "probe {probe_type}/{name}: threshold reached, restarting {service}"
                        );
                    }
                    match Command::new("systemctl")
                        .args(["restart", service])
                        .status()
                    {
                        Ok(s) if !s.success() => {
                            eprintln!(
                                "probe {probe_type}/{name}: systemctl restart {service} failed (exit {})",
                                s.code().unwrap_or(-1)
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "probe {probe_type}/{name}: systemctl restart {service}: {e}"
                            );
                        }
                        _ => {}
                    }
                }
                ProbeType::Readiness => {
                    let ready_file = format!("/oci/apps/{name}/probe-ready");
                    if let Err(e) = fs::write(&ready_file, "not-ready") {
                        eprintln!("probe {probe_type}/{name}: failed to write {ready_file}: {e}");
                    } else if verbose {
                        eprintln!("probe {probe_type}/{name}: not-ready");
                    }
                }
            }
        }

        // Always exit success: the probe binary manages its own failure tracking.
        // systemd should not mark the oneshot service as failed.
        ExitCode::SUCCESS
    }
}

fn read_fail_count(path: &str) -> u32 {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}
