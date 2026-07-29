//! OS-managed Unix listener activation with no self-bind fallback.

#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::os::{
    fd::{FromRawFd, OwnedFd},
    unix::net::UnixListener,
};

#[derive(Debug, thiserror::Error)]
pub enum ActivationError {
    #[error("service activation rejected: {0}")]
    Rejected(String),
    #[error("service activation I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(any(target_os = "linux", test))]
struct NamedActivation {
    descriptors: BTreeMap<String, OwnedFd>,
}

#[cfg(any(target_os = "linux", test))]
impl NamedActivation {
    fn new(descriptors: Vec<(String, OwnedFd)>) -> Result<Self, ActivationError> {
        let mut named = BTreeMap::new();
        for (name, descriptor) in descriptors {
            if name.is_empty() || name.as_bytes().contains(&0) {
                return Err(ActivationError::Rejected(
                    "activation socket name is invalid".into(),
                ));
            }
            if named.insert(name.clone(), descriptor).is_some() {
                return Err(ActivationError::Rejected(format!(
                    "activation socket name {name:?} is duplicated"
                )));
            }
        }
        Ok(Self { descriptors: named })
    }

    fn take(&mut self, name: &str) -> Result<OwnedFd, ActivationError> {
        self.descriptors.remove(name).ok_or_else(|| {
            ActivationError::Rejected(format!(
                "activation socket {name:?} was not provided or was already consumed"
            ))
        })
    }
}

/// Takes exactly one OS-managed Unix listener for `name`.
///
/// There is deliberately no path-binding fallback. A process outside its
/// launch manager fails closed instead of creating a weaker endpoint.
pub fn take_unix_listener(name: &str) -> Result<UnixListener, ActivationError> {
    let listener = UnixListener::from(take_fd(name)?);
    listener.set_nonblocking(true)?;
    listener.local_addr().map_err(ActivationError::Io)?;
    Ok(listener)
}

/// Takes exactly one OS-managed TCP listener for `name`.
pub fn take_tcp_listener(name: &str) -> Result<TcpListener, ActivationError> {
    let listener = TcpListener::from(take_fd(name)?);
    listener.set_nonblocking(true)?;
    listener.local_addr().map_err(ActivationError::Io)?;
    Ok(listener)
}

fn take_fd(name: &str) -> Result<OwnedFd, ActivationError> {
    if name.is_empty() || name.as_bytes().contains(&0) {
        return Err(ActivationError::Rejected(
            "activation socket name is invalid".into(),
        ));
    }
    #[cfg(target_os = "macos")]
    let descriptor = macos::take(name)?;
    #[cfg(target_os = "linux")]
    let descriptor = linux::take(name)?;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return Err(ActivationError::Rejected(
        "this platform has no reviewed activation adapter".into(),
    ));

    Ok(descriptor)
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::{ffi::CString, ptr};

    #[link(name = "System")]
    unsafe extern "C" {
        fn launch_activate_socket(
            name: *const libc::c_char,
            fds: *mut *mut libc::c_int,
            count: *mut libc::size_t,
        ) -> libc::c_int;
    }

    pub(super) fn take(name: &str) -> Result<OwnedFd, ActivationError> {
        let name = CString::new(name)
            .map_err(|_| ActivationError::Rejected("activation name contains NUL".into()))?;
        let mut raw_fds: *mut libc::c_int = ptr::null_mut();
        let mut count: libc::size_t = 0;
        // SAFETY: launch_activate_socket initializes the out pointer/count on
        // success. The returned allocation is released with libc::free below.
        let status = unsafe { launch_activate_socket(name.as_ptr(), &mut raw_fds, &mut count) };
        if status != 0 {
            return Err(ActivationError::Rejected(format!(
                "launchd did not provide socket {name:?} (status {status})"
            )));
        }
        if raw_fds.is_null() || count != 1 {
            if !raw_fds.is_null() {
                // SAFETY: launchd returned `count` initialized descriptors.
                let descriptors = unsafe { std::slice::from_raw_parts(raw_fds, count) };
                for descriptor in descriptors {
                    // SAFETY: descriptors are owned by this activation result.
                    unsafe { libc::close(*descriptor) };
                }
                // SAFETY: launch_activate_socket documents a malloc allocation.
                unsafe { libc::free(raw_fds.cast()) };
            }
            return Err(ActivationError::Rejected(format!(
                "launchd must provide exactly one socket, received {count}"
            )));
        }
        // SAFETY: count is exactly one and raw_fds is non-null.
        let descriptor = unsafe { *raw_fds };
        // SAFETY: launch_activate_socket documents a malloc allocation.
        unsafe { libc::free(raw_fds.cast()) };
        // SAFETY: this function takes sole ownership of the activated fd.
        let owned = unsafe { OwnedFd::from_raw_fd(descriptor) };
        Ok(owned)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    pub(super) fn take(name: &str) -> Result<OwnedFd, ActivationError> {
        static ACTIVATION: OnceLock<Result<Mutex<NamedActivation>, String>> = OnceLock::new();
        let activation = ACTIVATION.get_or_init(load);
        let activation = activation
            .as_ref()
            .map_err(|message| ActivationError::Rejected(message.clone()))?;
        activation
            .lock()
            .map_err(|_| ActivationError::Rejected("activation state lock was poisoned".into()))?
            .take(name)
    }

    fn load() -> Result<Mutex<NamedActivation>, String> {
        let pid = std::env::var("LISTEN_PID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok());
        let count = std::env::var("LISTEN_FDS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| "systemd LISTEN_FDS is missing or invalid".to_string())?;
        if pid != Some(std::process::id()) {
            return Err("systemd LISTEN_PID does not identify this process".into());
        }
        if count == 0 || count > 1_024 {
            return Err("systemd LISTEN_FDS is outside the reviewed range".into());
        }
        let names = std::env::var("LISTEN_FDNAMES")
            .map_err(|_| "systemd LISTEN_FDNAMES is missing".to_string())?;
        let names = names.split(':').collect::<Vec<_>>();
        if names.len() != count {
            return Err("systemd descriptor count and name count differ".into());
        }

        let mut descriptors = Vec::with_capacity(count);
        for (index, name) in names.into_iter().enumerate() {
            let raw = 3_i32
                .checked_add(
                    i32::try_from(index)
                        .map_err(|_| "systemd descriptor index is out of range".to_string())?,
                )
                .ok_or_else(|| "systemd descriptor number overflowed".to_string())?;
            // SAFETY: fcntl only inspects the descriptor. LISTEN_PID proves
            // that this descriptor set was assigned to the current process.
            if unsafe { libc::fcntl(raw, libc::F_GETFD) } == -1 {
                return Err(format!("systemd descriptor {raw} is not open"));
            }
            // SAFETY: systemd assigns ownership of descriptors 3..3+count to
            // this process. `ACTIVATION` initializes once, so each is adopted
            // exactly once and `NamedActivation::take` consumes it once.
            descriptors.push((name.to_string(), unsafe { OwnedFd::from_raw_fd(raw) }));
        }
        NamedActivation::new(descriptors)
            .map(Mutex::new)
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::OwnedFd;

    #[test]
    fn two_named_listeners_are_selected_and_consumed_independently() {
        let directory = tempfile::tempdir().unwrap();
        let rpc_path = directory.path().join("signer.sock");
        let control_path = directory.path().join("signer-control.sock");
        let rpc = UnixListener::bind(&rpc_path).unwrap();
        let control = UnixListener::bind(&control_path).unwrap();
        let mut activation = NamedActivation::new(vec![
            ("signer".into(), OwnedFd::from(rpc)),
            ("signer-control".into(), OwnedFd::from(control)),
        ])
        .unwrap();

        assert_eq!(
            UnixListener::from(activation.take("signer-control").unwrap())
                .local_addr()
                .unwrap()
                .as_pathname(),
            Some(control_path.as_path())
        );
        assert_eq!(
            UnixListener::from(activation.take("signer").unwrap())
                .local_addr()
                .unwrap()
                .as_pathname(),
            Some(rpc_path.as_path())
        );
        assert!(activation.take("signer").is_err());
    }
}
