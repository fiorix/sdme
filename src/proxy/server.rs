//! sdme-connector-server: socket-activated proxy server.
//!
//! Receives a listening socket from systemd socket activation (fd 3),
//! accepts one connection at a time, receives the client's stdin/stdout/stderr
//! via SCM_RIGHTS, forks and execs the configured entrypoint, and reports
//! the exit code back to the client.
//!
//! Usage: sdme-connector-server <entrypoint> [entrypoint-args...]
//!
//! The entrypoint is the command to execute. Client-provided argv is
//! appended to the entrypoint arguments. Environment and working directory
//! are inherited from the server process (set by the systemd unit), not
//! from the client. This is an intentional privilege separation design.

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::process::ExitCode;

use sdme::proxy;

/// The listening socket fd provided by systemd socket activation.
const SD_LISTEN_FD: RawFd = 3;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: sdme-connector-server <entrypoint> [args...]");
        return ExitCode::from(1);
    }
    let entrypoint = &args[1..];

    // Validate LISTEN_FDS from systemd socket activation.
    match std::env::var("LISTEN_FDS") {
        Ok(val) => {
            let n: i32 = match val.parse() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("error: LISTEN_FDS is not an integer: {val}");
                    return ExitCode::from(1);
                }
            };
            if n < 1 {
                eprintln!("error: LISTEN_FDS={n}, expected at least 1");
                return ExitCode::from(1);
            }
        }
        Err(_) => {
            eprintln!("error: LISTEN_FDS not set (not running under socket activation?)");
            return ExitCode::from(1);
        }
    }

    // Accept loop: one connection at a time.
    loop {
        let conn = unsafe { libc::accept(SD_LISTEN_FD, std::ptr::null_mut(), std::ptr::null_mut()) };
        if conn < 0 {
            let err = std::io::Error::last_os_error();
            // EINTR: check if we should exit.
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("error: accept failed: {err}");
            return ExitCode::from(1);
        }

        if let Err(e) = handle_connection(conn, entrypoint) {
            eprintln!("error: connection failed: {e}");
        }
        proxy::close_fd(conn);
    }
}

fn handle_connection(conn: RawFd, entrypoint: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Receive the request + fds from the client.
    // The client sends a length-prefixed JSON frame with SCM_RIGHTS carrying 3 fds.
    let mut buf = [0u8; 65536];
    let (n, fds) = proxy::recv_with_fds(conn, &mut buf, 3)?;

    if fds.len() != 3 {
        // Clean up any fds we did receive.
        for fd in &fds {
            proxy::close_fd(*fd);
        }
        return Err(format!("expected 3 file descriptors, got {}", fds.len()).into());
    }

    let client_stdin = fds[0];
    let client_stdout = fds[1];
    let client_stderr = fds[2];

    // Parse the length-prefixed frame from the received bytes.
    if n < 4 {
        for fd in &fds {
            proxy::close_fd(*fd);
        }
        return Err("message too short for frame header".into());
    }
    let payload_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if 4 + payload_len > n {
        for fd in &fds {
            proxy::close_fd(*fd);
        }
        return Err(format!(
            "incomplete frame: expected {} payload bytes, got {}",
            payload_len,
            n - 4
        )
        .into());
    }

    let request: proxy::ProxyRequest = serde_json::from_slice(&buf[4..4 + payload_len])?;

    // Build the full command: entrypoint args + client args.
    let mut cmd_args: Vec<CString> = Vec::new();
    for arg in entrypoint {
        cmd_args.push(CString::new(arg.as_bytes())?);
    }
    for arg in &request.argv {
        cmd_args.push(CString::new(arg.as_bytes())?);
    }

    // Fork and exec.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let err = std::io::Error::last_os_error();
        proxy::close_fd(client_stdin);
        proxy::close_fd(client_stdout);
        proxy::close_fd(client_stderr);
        return Err(format!("fork failed: {err}").into());
    }

    if pid == 0 {
        // Child process.

        // Close the listening socket and connection socket in the child.
        proxy::close_fd(SD_LISTEN_FD);
        proxy::close_fd(conn);

        // Create a new session so we can acquire a controlling terminal.
        unsafe {
            libc::setsid();
        }

        // Set up stdin/stdout/stderr from the client's fds.
        unsafe {
            libc::dup2(client_stdin, 0);
            libc::dup2(client_stdout, 1);
            libc::dup2(client_stderr, 2);
        }

        // Close the original received fds if they aren't 0, 1, or 2.
        for &fd in &[client_stdin, client_stdout, client_stderr] {
            if fd > 2 {
                proxy::close_fd(fd);
            }
        }

        // If stdin is a terminal, make it the controlling terminal.
        if unsafe { libc::isatty(0) } == 1 {
            unsafe {
                libc::ioctl(0, libc::TIOCSCTTY, 0);
            }
        }

        // Exec the entrypoint.
        let argv_ptrs: Vec<*const libc::c_char> = cmd_args
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        unsafe {
            libc::execvp(argv_ptrs[0], argv_ptrs.as_ptr());
        }

        // If execvp returns, it failed.
        let err = std::io::Error::last_os_error();
        eprintln!(
            "error: exec failed: {}: {}",
            cmd_args[0].to_string_lossy(),
            err
        );
        unsafe {
            libc::_exit(127);
        }
    }

    // Parent process.
    // Close the client's fds; the child owns them now.
    proxy::close_fd(client_stdin);
    proxy::close_fd(client_stdout);
    proxy::close_fd(client_stderr);

    // Wait for the child.
    let mut status: libc::c_int = 0;
    loop {
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("waitpid failed: {err}").into());
        }
        break;
    }

    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    };

    // Send the exit code back to the client.
    let response = proxy::ProxyResponse { exit_code };
    let payload = serde_json::to_vec(&response)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);

    let written = unsafe {
        libc::send(
            conn,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
        )
    };
    if written < 0 {
        // Client may have disconnected; log but don't fail.
        let err = std::io::Error::last_os_error();
        eprintln!("warning: failed to send response: {err}");
    }

    Ok(())
}
