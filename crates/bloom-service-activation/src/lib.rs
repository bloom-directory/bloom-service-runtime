//! Reviewed Unix listener acquisition with no opportunistic fallback.
//!
//! Linux services consume systemd-activated listeners. The root-requiring
//! macOS profile explicitly selects service-owned path binding because a
//! launchd-created Unix socket reports launchd's UID to the connecting peer.

#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeMap;
use std::os::{
    fd::{FromRawFd, OwnedFd},
    unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    unix::net::UnixListener,
};
use std::{fs, net::TcpListener, path::Path};

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

/// Binds and publishes a Unix listener in a service-owned endpoint directory.
///
/// This is an explicit activation mode for the reviewed macOS package, not a
/// fallback from OS activation. The parent must be a real directory owned by
/// the effective service UID with mode `0710`. Its group becomes the socket
/// group. Existing live sockets and unsafe stale entries are rejected.
pub fn bind_owned_unix_listener(path: &Path) -> Result<UnixListener, ActivationError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ActivationError::Rejected(
            "owned Unix listener path must be an absolute file path".into(),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        ActivationError::Rejected("owned Unix listener path has no parent".into())
    })?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    let effective_uid = unsafe { libc::geteuid() };
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != effective_uid
        || parent_metadata.mode() & 0o777 != 0o710
    {
        return Err(ActivationError::Rejected(format!(
            "endpoint directory {} must be a non-symlink directory owned by effective UID {} with mode 0710",
            parent.display(),
            effective_uid
        )));
    }

    remove_owned_stale_socket(path, effective_uid)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ActivationError::Rejected("socket filename is not UTF-8".into()))?;
    let temporary = parent.join(format!(".{file_name}.new.{}", std::process::id()));
    if fs::symlink_metadata(&temporary).is_ok() {
        return Err(ActivationError::Rejected(format!(
            "temporary endpoint {} already exists",
            temporary.display()
        )));
    }

    let listener = UnixListener::bind(&temporary)?;
    let result = (|| {
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o660))?;
        std::os::unix::fs::chown(&temporary, None, Some(parent_metadata.gid()))?;
        require_socket_metadata(
            &temporary,
            effective_uid,
            parent_metadata.gid(),
            "new endpoint",
        )?;
        fs::rename(&temporary, path)?;
        require_socket_metadata(
            path,
            effective_uid,
            parent_metadata.gid(),
            "published endpoint",
        )?;
        listener.set_nonblocking(true)?;
        Ok(listener)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn remove_owned_stale_socket(path: &Path, effective_uid: u32) -> Result<(), ActivationError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid
        || metadata.nlink() != 1
    {
        return Err(ActivationError::Rejected(format!(
            "existing endpoint {} is not a singly-linked socket owned by effective UID {}",
            path.display(),
            effective_uid
        )));
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(ActivationError::Rejected(format!(
            "existing endpoint {} is live",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) => Err(ActivationError::Rejected(format!(
            "cannot prove existing endpoint {} is stale: {}",
            path.display(),
            error
        ))),
    }
}

fn require_socket_metadata(
    path: &Path,
    uid: u32,
    gid: u32,
    description: &str,
) -> Result<(), ActivationError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o777 != 0o660
        || metadata.nlink() != 1
    {
        return Err(ActivationError::Rejected(format!(
            "{description} {} has unsafe type, ownership, mode, or link count",
            path.display()
        )));
    }
    Ok(())
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

    #[test]
    fn owned_listener_publishes_exact_edge_metadata_and_rejects_live_replacement() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o710)).unwrap();
        let socket_path = directory.path().join("broker.sock");

        let listener = bind_owned_unix_listener(&socket_path).unwrap();
        let metadata = fs::symlink_metadata(&socket_path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(
            metadata.gid(),
            fs::metadata(directory.path()).unwrap().gid()
        );
        assert_eq!(metadata.mode() & 0o777, 0o660);

        let error = bind_owned_unix_listener(&socket_path).unwrap_err();
        assert!(error.to_string().contains("is live"));
        drop(listener);
    }

    #[test]
    fn owned_listener_replaces_only_a_safe_stale_socket() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o710)).unwrap();
        let socket_path = directory.path().join("signer.sock");
        drop(UnixListener::bind(&socket_path).unwrap());
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660)).unwrap();

        let listener = bind_owned_unix_listener(&socket_path).unwrap();
        assert!(listener.local_addr().is_ok());
    }

    #[test]
    fn owned_listener_rejects_non_socket_substitution() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o710)).unwrap();
        let socket_path = directory.path().join("broker.sock");
        fs::write(&socket_path, b"substitution").unwrap();

        let error = bind_owned_unix_listener(&socket_path).unwrap_err();
        assert!(error.to_string().contains("not a singly-linked socket"));
    }
}
