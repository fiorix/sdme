//! sdme-connector-client: connects to a proxy server via a connector socket.
//!
//! Sends the client's stdin/stdout/stderr file descriptors to the proxy
//! server via SCM_RIGHTS, along with command arguments, and waits for
//! the exit code.
//!
//! Invocation styles:
//!
//! 1. Explicit:
//!    sdme-connector-client --connector-dir=/connectors/svc --name=svc [args...]
//!
//! 2. Busybox-style (via symlink):
//!    ln -s /usr/libexec/sdme-connector-client /connectors/svc/nginx
//!    /connectors/svc/nginx [args...]
//!    → name = "nginx", connector-dir from SDME_CONNECTOR_DIR env var
//!
//! The client does NOT send its environment or working directory.
//! This is intentional: the server controls the execution context.

use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::process::ExitCode;

use sdme::proxy;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("sdme-connector-client: {e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let raw_args: Vec<String> = std::env::args().collect();

    // Determine the invocation mode.
    let argv0 = &raw_args[0];
    let basename = PathBuf::from(argv0)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let (connector_dir, name, client_argv) = if basename != "sdme-connector-client" {
        // Busybox-style: name from argv[0], args are everything after.
        let dir = std::env::var("SDME_CONNECTOR_DIR").map_err(|_| {
            "SDME_CONNECTOR_DIR not set (required for busybox-style invocation)"
        })?;
        (dir, basename, raw_args[1..].to_vec())
    } else {
        // Explicit mode: parse --connector-dir and --name flags.
        parse_explicit_args(&raw_args[1..])?
    };

    // Connect to the server socket.
    let sock_path = format!("{connector_dir}/{name}.sock");
    let conn = connect_unix(&sock_path)?;

    // Build and send the request with SCM_RIGHTS.
    let request = proxy::ProxyRequest { argv: client_argv };
    let payload = serde_json::to_vec(&request)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);

    // Send the frame + our stdin/stdout/stderr fds.
    proxy::send_with_fds(conn, &frame, &[0, 1, 2])?;

    // Wait for the response.
    let mut buf = [0u8; 4096];
    let n = {
        let ret = unsafe {
            libc::recv(conn, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };
        if ret < 0 {
            return Err(format!("recv failed: {}", std::io::Error::last_os_error()).into());
        }
        if ret == 0 {
            return Err("server closed connection without response".into());
        }
        ret as usize
    };

    proxy::close_fd(conn);

    // Parse the length-prefixed response.
    if n < 4 {
        return Err("response too short for frame header".into());
    }
    let payload_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if 4 + payload_len > n {
        return Err(format!(
            "incomplete response: expected {} payload bytes, got {}",
            payload_len,
            n - 4
        )
        .into());
    }

    let response: proxy::ProxyResponse = serde_json::from_slice(&buf[4..4 + payload_len])?;
    Ok(response.exit_code)
}

/// Parse explicit-mode arguments: --connector-dir=DIR --name=NAME [args...]
fn parse_explicit_args(
    args: &[String],
) -> Result<(String, String, Vec<String>), Box<dyn std::error::Error>> {
    let mut connector_dir: Option<String> = None;
    let mut name: Option<String> = None;
    let mut rest_start = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(val) = arg.strip_prefix("--connector-dir=") {
            connector_dir = Some(val.to_string());
        } else if arg == "--connector-dir" {
            i += 1;
            connector_dir = Some(
                args.get(i)
                    .ok_or("--connector-dir requires a value")?
                    .clone(),
            );
        } else if let Some(val) = arg.strip_prefix("--name=") {
            name = Some(val.to_string());
        } else if arg == "--name" {
            i += 1;
            name = Some(args.get(i).ok_or("--name requires a value")?.clone());
        } else {
            rest_start = i;
            break;
        }
        i += 1;
        rest_start = i;
    }

    let connector_dir = connector_dir.or_else(|| std::env::var("SDME_CONNECTOR_DIR").ok())
        .ok_or("--connector-dir or SDME_CONNECTOR_DIR required")?;
    let name = name.ok_or("--name required in explicit mode")?;

    Ok((connector_dir, name, args[rest_start..].to_vec()))
}

/// Connect to a Unix stream socket at the given path.
fn connect_unix(path: &str) -> Result<RawFd, Box<dyn std::error::Error>> {
    use std::ffi::CString;

    let sock = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if sock < 0 {
        return Err(format!("socket failed: {}", std::io::Error::last_os_error()).into());
    }

    let c_path = CString::new(path)?;
    let path_bytes = c_path.as_bytes_with_nul();

    // sun_path is 108 bytes on Linux.
    if path_bytes.len() > 108 {
        proxy::close_fd(sock);
        return Err(format!("socket path too long ({} bytes, max 108): {path}", path_bytes.len()).into());
    }

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    unsafe {
        std::ptr::copy_nonoverlapping(
            path_bytes.as_ptr(),
            addr.sun_path.as_mut_ptr(),
            path_bytes.len(),
        );
    }

    let addr_len = std::mem::size_of::<libc::sa_family_t>() + path_bytes.len();
    let ret = unsafe {
        libc::connect(
            sock,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            addr_len as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        proxy::close_fd(sock);
        return Err(format!("connect to {path} failed: {err}").into());
    }

    Ok(sock)
}
