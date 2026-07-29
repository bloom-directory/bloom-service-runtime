#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs,
        io::{Read, Write},
        os::unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
        path::Path,
        process::Command,
        time::Duration,
    };

    const MACHINE_UID: u32 = 62_001;
    const BROKER_UID: u32 = 62_002;
    const SIGNER_UID: u32 = 62_003;
    const MACHINE_BROKER_GID: u32 = 62_101;
    const BROKER_SIGNER_GID: u32 = 62_102;
    const REVOKE_GID: u32 = 62_103;
    const HELPER_ENV: &str = "BLOOM_LINUX_W0_HELPER";

    #[test]
    fn machine_cannot_read_service_state_or_open_the_signer_edge() {
        if let Some(mode) = std::env::var_os(HELPER_ENV) {
            helper(&mode.to_string_lossy());
            return;
        }
        if std::env::var_os("BLOOM_RUN_LINUX_PRIVILEGED_W0").is_none()
            || unsafe { libc::geteuid() } != 0
        {
            eprintln!(
                "Linux UID isolation runs only in the explicit privileged W0 CI lane; local tests make no identity or service changes"
            );
            return;
        }

        let root = tempfile::tempdir().expect("temporary isolation root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o711)).unwrap();
        let broker_state = private_state(root.path(), "broker", BROKER_UID);
        let signer_state = private_state(root.path(), "signer", SIGNER_UID);

        assert_child_denied(
            "machine-read",
            &[broker_state.to_str().unwrap()],
            MACHINE_UID,
            MACHINE_UID,
            &[MACHINE_BROKER_GID, REVOKE_GID],
        );
        assert_child_denied(
            "machine-read",
            &[signer_state.to_str().unwrap()],
            MACHINE_UID,
            MACHINE_UID,
            &[MACHINE_BROKER_GID, REVOKE_GID],
        );

        let socket_path = root.path().join("signer.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind Signer edge");
        chown(&socket_path, SIGNER_UID, BROKER_SIGNER_GID);
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660)).unwrap();
        assert_child_denied(
            "connect",
            &[socket_path.to_str().unwrap()],
            MACHINE_UID,
            MACHINE_UID,
            &[MACHINE_BROKER_GID, REVOKE_GID],
        );

        listener
            .set_nonblocking(true)
            .expect("make Signer edge bounded");
        let mut child = child(
            "connect",
            &[socket_path.to_str().unwrap()],
            BROKER_UID,
            BROKER_UID,
            &[MACHINE_BROKER_GID, BROKER_SIGNER_GID],
        )
        .spawn()
        .expect("spawn Broker-principal connector");
        let mut accepted = None;
        for _ in 0..100 {
            match listener.accept() {
                Ok(pair) => {
                    accepted = Some(pair.0);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept Broker-principal connector: {error}"),
            }
        }
        let mut stream = accepted.expect("Broker principal did not reach Signer socket");
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [0x42]);
        assert!(child.wait().unwrap().success());
    }

    fn private_state(root: &Path, name: &str, owner: u32) -> std::path::PathBuf {
        let directory = root.join(name);
        fs::create_dir(&directory).unwrap();
        chown(&directory, owner, owner);
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let state = directory.join("state");
        fs::write(&state, b"principal-private").unwrap();
        chown(&state, owner, owner);
        fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::metadata(&state).unwrap().uid(), owner);
        state
    }

    fn assert_child_denied(mode: &str, arguments: &[&str], uid: u32, gid: u32, groups: &[u32]) {
        let status = child(mode, arguments, uid, gid, groups)
            .status()
            .expect("run denied principal");
        assert_eq!(
            status.code(),
            Some(77),
            "{mode} unexpectedly succeeded or failed outside the expected DAC denial: {status}"
        );
    }

    fn child(mode: &str, arguments: &[&str], uid: u32, gid: u32, groups: &[u32]) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("linux::machine_cannot_read_service_state_or_open_the_signer_edge")
            .arg("--nocapture")
            .env(HELPER_ENV, mode)
            .env("BLOOM_LINUX_W0_UID", uid.to_string())
            .env("BLOOM_LINUX_W0_GID", gid.to_string())
            .env(
                "BLOOM_LINUX_W0_GROUPS",
                groups
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .env(
                "BLOOM_LINUX_W0_TARGET",
                arguments.first().expect("helper target argument"),
            );
        command
    }

    fn helper(mode: &str) {
        let target = std::env::var("BLOOM_LINUX_W0_TARGET").expect("helper target");
        drop_identity();
        let result = match mode {
            "machine-read" => fs::read(&target).map(|_| ()),
            "connect" => {
                UnixStream::connect(&target).and_then(|mut stream| stream.write_all(&[0x42]))
            }
            other => panic!("unknown helper mode {other}"),
        };
        match result {
            Ok(()) => std::process::exit(0),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                std::process::exit(77)
            }
            Err(error) => panic!("{mode} failed with unexpected error: {error}"),
        }
    }

    fn drop_identity() {
        let uid = env_number("BLOOM_LINUX_W0_UID");
        let gid = env_number("BLOOM_LINUX_W0_GID");
        let groups = std::env::var("BLOOM_LINUX_W0_GROUPS")
            .unwrap()
            .split(',')
            .map(|value| value.parse::<libc::gid_t>().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            unsafe { libc::setgroups(groups.len(), groups.as_ptr()) },
            0,
            "setgroups failed"
        );
        assert_eq!(unsafe { libc::setgid(gid) }, 0, "setgid failed");
        assert_eq!(unsafe { libc::setuid(uid) }, 0, "setuid failed");
    }

    fn env_number(name: &str) -> u32 {
        std::env::var(name).unwrap().parse().unwrap()
    }

    fn chown(path: &Path, uid: u32, gid: u32) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(path.as_ptr(), uid, gid) },
            0,
            "chown failed"
        );
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn linux_uid_isolation_is_exercised_on_linux_ci() {}
