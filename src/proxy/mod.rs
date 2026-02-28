//! Shared proxy protocol types and Unix socket helpers.
//!
//! Defines the JSON wire protocol and SCM_RIGHTS file descriptor passing
//! used by `sdme-connector-server` and `sdme-connector-client`.
//!
//! **Design decision (privilege separation)**: The client sends only argv
//! and its stdin/stdout/stderr file descriptors. Environment variables and
//! working directory are NOT sent; the server inherits these from its own
//! process context (set by the container's systemd unit). This provides
//! strong privilege separation: the server container controls the execution
//! environment, not the caller.

use std::io::{self, Read, Write};
use std::os::unix::io::RawFd;

use serde::{Deserialize, Serialize};

/// Client-to-server request. Contains only the command arguments.
///
/// The server appends these to the entrypoint command configured at
/// server startup. Environment and cwd are intentionally omitted for
/// privilege separation.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyRequest {
    pub argv: Vec<String>,
}

/// Server-to-client response. Contains the exit code of the executed command.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyResponse {
    pub exit_code: i32,
}

/// Write a length-prefixed frame to a writer.
///
/// Format: `[4-byte big-endian length][payload]`.
pub fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(data)?;
    w.flush()
}

/// Read a length-prefixed frame from a reader.
///
/// Returns the payload bytes. The maximum payload size is 1 MiB.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

// --- SCM_RIGHTS file descriptor passing ---

/// Send data along with file descriptors via SCM_RIGHTS on a Unix socket.
///
/// The `fds` slice contains file descriptors to pass to the peer process.
/// The `data` slice contains the message payload.
pub fn send_with_fds(sock: RawFd, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    use std::mem;
    use std::ptr;

    let iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };

    // Compute the cmsg buffer size for the fds.
    let fds_size = mem::size_of_val(fds);
    let cmsg_space = unsafe { libc::CMSG_SPACE(fds_size as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    // Fill in the control message header.
    let cmsg: *mut libc::cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::other("CMSG_FIRSTHDR returned null"));
    }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fds_size as u32) as _;
        ptr::copy_nonoverlapping(
            fds.as_ptr() as *const u8,
            libc::CMSG_DATA(cmsg),
            fds_size,
        );
    }

    let sent = unsafe { libc::sendmsg(sock, &msg, 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if (sent as usize) != data.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "sendmsg: short write",
        ));
    }
    Ok(())
}

/// Receive data and file descriptors via SCM_RIGHTS from a Unix socket.
///
/// Returns `(bytes_read, received_fds)`. `max_fds` is the maximum number
/// of file descriptors to accept.
pub fn recv_with_fds(
    sock: RawFd,
    buf: &mut [u8],
    max_fds: usize,
) -> io::Result<(usize, Vec<RawFd>)> {
    use std::mem;

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let fds_size = max_fds * mem::size_of::<RawFd>();
    let cmsg_space = unsafe { libc::CMSG_SPACE(fds_size as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed",
        ));
    }

    // Extract file descriptors from ancillary data.
    let mut fds = Vec::new();
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        unsafe {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_ptr = libc::CMSG_DATA(cmsg);
                let data_len =
                    (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let num_fds = data_len / mem::size_of::<RawFd>();
                for i in 0..num_fds {
                    let fd_ptr =
                        data_ptr.add(i * mem::size_of::<RawFd>()) as *const RawFd;
                    fds.push(fd_ptr.read_unaligned());
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok((n as usize, fds))
}

/// Close a file descriptor, ignoring errors.
pub fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_request_serialization() {
        let req = ProxyRequest {
            argv: vec!["--config".to_string(), "/etc/app.conf".to_string()],
        };
        let json = serde_json::to_vec(&req).unwrap();
        let parsed: ProxyRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.argv, req.argv);
    }

    #[test]
    fn test_proxy_response_serialization() {
        let resp = ProxyResponse { exit_code: 42 };
        let json = serde_json::to_vec(&resp).unwrap();
        let parsed: ProxyResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.exit_code, 42);
    }

    #[test]
    fn test_frame_roundtrip() {
        let data = b"hello world";
        let mut buf = Vec::new();
        write_frame(&mut buf, data).unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_frame_empty() {
        let data = b"";
        let mut buf = Vec::new();
        write_frame(&mut buf, data).unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_frame_too_large() {
        // Forge a frame header claiming 2 MiB.
        let len: u32 = 2 * 1024 * 1024;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(b"x"); // partial data

        let mut cursor = std::io::Cursor::new(buf);
        let err = read_frame(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_scm_rights_roundtrip() {
        // Create a Unix socketpair and send/receive fds.
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair failed");

        let (sender, receiver) = (fds[0], fds[1]);

        // Create a pipe; we'll send the read end to the peer.
        let mut pipe_fds = [0i32; 2];
        let ret = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "pipe failed");
        let (pipe_read, pipe_write) = (pipe_fds[0], pipe_fds[1]);

        // Send the pipe read fd via SCM_RIGHTS.
        let msg = b"hello";
        send_with_fds(sender, msg, &[pipe_read]).unwrap();

        // Receive on the other end.
        let mut buf = [0u8; 64];
        let (n, received_fds) = recv_with_fds(receiver, &mut buf, 4).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(received_fds.len(), 1);

        // Write through the original pipe write end and read from the received fd.
        let test_data = b"test";
        let written = unsafe {
            libc::write(
                pipe_write,
                test_data.as_ptr() as *const libc::c_void,
                test_data.len(),
            )
        };
        assert_eq!(written as usize, test_data.len());

        let mut read_buf = [0u8; 16];
        let read_n = unsafe {
            libc::read(
                received_fds[0],
                read_buf.as_mut_ptr() as *mut libc::c_void,
                read_buf.len(),
            )
        };
        assert_eq!(read_n as usize, test_data.len());
        assert_eq!(&read_buf[..read_n as usize], test_data);

        // Clean up.
        close_fd(sender);
        close_fd(receiver);
        close_fd(pipe_read);
        close_fd(pipe_write);
        close_fd(received_fds[0]);
    }
}
