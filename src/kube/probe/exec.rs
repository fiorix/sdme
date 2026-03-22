//! Exec probe: chroot into app root and run a command.

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Run a command inside the app root via chroot with a timeout.
pub fn check(app_root: &str, timeout_secs: u32, command: &[String]) -> bool {
    if command.is_empty() {
        return false;
    }

    let c_root = match std::ffi::CString::new(app_root) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let result = unsafe {
        Command::new(&command[0])
            .args(&command[1..])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .pre_exec(move || {
                if libc::chroot(c_root.as_ptr()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::chdir(c"/".as_ptr()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
            .spawn()
    };

    let mut child = match result {
        Ok(c) => c,
        Err(_) => return false,
    };

    let deadline = Instant::now() + Duration::from_secs(timeout_secs as u64);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return false,
        }
    }
}
