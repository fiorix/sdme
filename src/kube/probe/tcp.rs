//! TCP probe: check port connectivity.

use std::net::TcpStream;
use std::time::Duration;

/// Check if a TCP connection can be established within the timeout.
pub fn check(port: u16, timeout_secs: u32) -> bool {
    let timeout = Duration::from_secs(timeout_secs as u64);
    let addr: std::net::SocketAddr = match format!("127.0.0.1:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    TcpStream::connect_timeout(&addr, timeout).is_ok()
}
