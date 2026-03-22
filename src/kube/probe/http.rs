//! HTTP probe: raw HTTP/1.0 GET using std TcpStream.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Send an HTTP GET request and check for a 2xx/3xx status code.
///
/// Custom headers are passed as pre-formatted `"Name: Value"` strings
/// and appended to the request before the final blank line.
pub fn check(port: u16, path: &str, scheme: &str, headers: &[String], timeout_secs: u32) -> bool {
    if scheme == "https" {
        eprintln!("sdme-kube-probe: HTTPS probes not supported, using HTTP");
    }

    let timeout = Duration::from_secs(timeout_secs as u64);
    let addr: std::net::SocketAddr = match format!("127.0.0.1:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let mut request = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n");
    for h in headers {
        if h.contains('\r') || h.contains('\n') {
            continue; // skip malformed headers
        }
        request.push_str(h);
        request.push_str("\r\n");
    }
    request.push_str("Connection: close\r\n\r\n");

    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }

    let mut buf = [0u8; 256];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return false,
    };

    // Parse "HTTP/1.x NNN ..." from the first line.
    let response = String::from_utf8_lossy(&buf[..n]);
    if let Some(status_line) = response.lines().next() {
        if let Some(code_str) = status_line.split_whitespace().nth(1) {
            if let Ok(code) = code_str.parse::<u16>() {
                return (200..400).contains(&code);
            }
        }
    }

    false
}
