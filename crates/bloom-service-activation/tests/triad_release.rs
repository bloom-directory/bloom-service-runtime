use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command,
};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf()
}

fn release_script(name: &str) -> PathBuf {
    workspace().join("packaging/triad/release").join(name)
}

fn make_staging(root: &Path) -> PathBuf {
    let staging = root.join("staging");
    fs::create_dir_all(staging.join("bin")).unwrap();
    for binary in ["bloom", "bloom-broker", "bloom-signer"] {
        let path = staging.join("bin").join(binary);
        let version = if binary == "bloom" { "0.1.1" } else { "0.1.0" };
        fs::write(&path, format!("#!/bin/sh\necho {binary} {version}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::write(staging.join("PLATFORM_CLAIM"), b"test-unclaimed\n").unwrap();
    staging
}

fn make_installer_payload(root: &Path) -> PathBuf {
    let payload = make_staging(root);
    fs::create_dir_all(payload.join("config")).unwrap();
    for config in [
        "edge-manifest.json",
        "broker.json",
        "signer.json",
        "broker-identity.json",
        "signer-identity.json",
    ] {
        fs::write(payload.join("config").join(config), b"{}").unwrap();
    }
    fs::create_dir_all(payload.join("credentials")).unwrap();
    fs::write(
        payload.join("config/aws-kms-ip-allow.conf"),
        b"IPAddressAllow=192.0.2.0/24\n",
    )
    .unwrap();
    fs::write(
        payload.join("credentials/aws-credentials"),
        b"[default]\naws_access_key_id=test\n",
    )
    .unwrap();
    fs::write(
        payload.join("config/nts-servers.conf"),
        b"time.cloudflare.com\ntime.nist.gov\n",
    )
    .unwrap();
    payload
}

fn build(staging: &Path, output: &Path, key: &Path) -> std::process::Output {
    Command::new(release_script("build-bundle.sh"))
        .args([staging.as_os_str(), output.as_os_str(), key.as_os_str()])
        .arg("1700000000")
        .env("BLOOM_MACHINE_SHA", "1111111")
        .env("BLOOM_BROKER_SHA", "2222222")
        .env("BLOOM_SIGNER_SHA", "3333333")
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .output()
        .unwrap()
}

#[test]
fn acceptance_rerun_is_bound_to_the_verified_bundle_when_present() {
    let Some(bundle) = std::env::var_os("BLOOM_ACCEPTANCE_BUNDLE_ROOT") else {
        return;
    };
    let bundle = PathBuf::from(bundle);
    assert_eq!(
        fs::read_to_string(bundle.join("PLATFORM_CLAIM"))
            .unwrap()
            .trim(),
        if std::env::var("BLOOM_ALLOW_TEST_UNCLAIMED").as_deref() == Ok("true") {
            "test-unclaimed"
        } else {
            "linux"
        }
    );
    for (binary, version) in [
        ("bloom", "0.1.1"),
        ("bloom-broker", "0.1.0"),
        ("bloom-signer", "0.1.0"),
    ] {
        let output = Command::new(bundle.join("bin").join(binary))
            .arg("--version")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            format!("{binary} {version}")
        );
    }
}

#[test]
fn triad_bundle_is_reproducible_signed_and_self_verifying() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    let key = directory.path().join("release-key.pem");
    assert!(
        Command::new("openssl")
            .args(["genpkey", "-algorithm", "ED25519", "-out"])
            .arg(&key)
            .status()
            .unwrap()
            .success()
    );
    let first = directory.path().join("first.tar.gz");
    let second = directory.path().join("second.tar.gz");
    let first_build = build(&staging, &first, &key);
    assert!(
        first_build.status.success(),
        "{}",
        String::from_utf8_lossy(&first_build.stderr)
    );
    let second_build = build(&staging, &second, &key);
    assert!(
        second_build.status.success(),
        "{}",
        String::from_utf8_lossy(&second_build.stderr)
    );
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

    let checksum = PathBuf::from(format!("{}.sha256", first.display()));
    let signature = PathBuf::from(format!("{}.sig", first.display()));
    let public_key = PathBuf::from(format!("{}.pub", first.display()));
    let verified = Command::new(release_script("verify-bundle.sh"))
        .args([
            first.as_os_str(),
            checksum.as_os_str(),
            signature.as_os_str(),
            public_key.as_os_str(),
        ])
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
}

#[test]
fn release_scan_rejects_debug_or_accepting_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    fs::write(
        staging.join("bin/bloom-broker"),
        b"bloom-broker-debug-driver",
    )
    .unwrap();
    let key = directory.path().join("release-key.pem");
    assert!(
        Command::new("openssl")
            .args(["genpkey", "-algorithm", "ED25519", "-out"])
            .arg(&key)
            .status()
            .unwrap()
            .success()
    );
    let built = build(&staging, &directory.path().join("forbidden.tar.gz"), &key);
    assert!(!built.status.success());
    assert!(String::from_utf8_lossy(&built.stderr).contains("forbidden production artifact"));
}

#[test]
fn bundle_rejects_a_service_outside_the_current_only_matrix() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    fs::write(
        staging.join("bin/bloom-signer"),
        b"#!/bin/sh\necho bloom-signer 0.0.9\n",
    )
    .unwrap();
    let key = directory.path().join("release-key.pem");
    assert!(
        Command::new("openssl")
            .args(["genpkey", "-algorithm", "ED25519", "-out"])
            .arg(&key)
            .status()
            .unwrap()
            .success()
    );
    let built = build(&staging, &directory.path().join("old-signer.tar.gz"), &key);
    assert!(!built.status.success());
    assert!(String::from_utf8_lossy(&built.stderr).contains("compatibility matrix"));
}

#[test]
fn linux_installer_upgrade_rotation_and_confirmed_uninstall_are_staged_safely() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    let payload = make_installer_payload(directory.path());
    let installer = release_script("install-linux.sh");
    let install = Command::new(&installer)
        .args(["install"])
        .arg(&root)
        .args(["1000", "alice"])
        .arg(&payload)
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .output()
        .unwrap();
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    let broker_unit =
        fs::read_to_string(root.join("usr/lib/systemd/system/bloom-broker@.service")).unwrap();
    assert!(broker_unit.contains("ExecStart=/usr/libexec/bloom/bloom-broker"));
    assert!(!broker_unit.contains("@BLOOM_"));
    let sysusers = fs::read_to_string(root.join("usr/lib/sysusers.d/bloom-1000.conf")).unwrap();
    assert!(sysusers.contains("bloom-broker-1000"));
    assert!(sysusers.contains("alice"));
    let chrony = fs::read_to_string(root.join("etc/chrony/conf.d/bloom-nts.conf")).unwrap();
    assert!(chrony.contains("server time.cloudflare.com iburst nts"));
    assert!(chrony.contains("server time.nist.gov iburst nts"));
    assert_eq!(
        fs::metadata(root.join("etc/bloom/1000/signer/config.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let aws_dropin = fs::read_to_string(
        root.join("usr/lib/systemd/system/bloom-signer@1000.service.d/50-aws-kms.conf"),
    )
    .unwrap();
    assert!(aws_dropin.contains("IPAddressDeny=any"));
    assert!(aws_dropin.contains("IPAddressAllow=192.0.2.0/24"));
    assert!(!aws_dropin.contains("@AWS_KMS_IP_ALLOW_DIRECTIVES@"));

    fs::remove_file(payload.join("credentials/aws-credentials")).unwrap();
    fs::remove_file(payload.join("config/aws-kms-ip-allow.conf")).unwrap();
    fs::write(payload.join("bin/bloom-broker"), b"upgraded-broker").unwrap();
    assert!(
        Command::new(&installer)
            .args(["install"])
            .arg(&root)
            .args(["1000", "alice"])
            .arg(&payload)
            .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::read(root.join("usr/libexec/bloom/bloom-broker")).unwrap(),
        b"upgraded-broker"
    );
    assert!(!root.join("etc/bloom/1000/signer/aws-credentials").exists());
    assert!(
        !root
            .join("usr/lib/systemd/system/bloom-signer@1000.service.d/50-aws-kms.conf")
            .exists()
    );

    let rotated = directory.path().join("rotated.json");
    fs::write(&rotated, b"{\"rotated\":true}").unwrap();
    assert!(
        Command::new(&installer)
            .args(["rotate-config"])
            .arg(&root)
            .args(["1000", "signer"])
            .arg(&rotated)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::read(root.join("etc/bloom/1000/signer/config.json")).unwrap(),
        b"{\"rotated\":true}"
    );

    assert!(
        !Command::new(&installer)
            .args(["uninstall"])
            .arg(&root)
            .args(["1000", "wrong-confirmation"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&installer)
            .args(["uninstall"])
            .arg(&root)
            .args(["1000", "delete-bloom-login-1000"])
            .status()
            .unwrap()
            .success()
    );
    assert!(!root.join("etc/bloom/1000").exists());
    assert!(
        !root
            .join("usr/lib/systemd/system/bloom-signer@1000.service.d")
            .exists()
    );
    assert!(root.join("usr/libexec/bloom/bloom-broker").exists());
}

#[test]
fn macos_installer_renders_private_launchagents_and_confirmed_uninstall() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    let payload = make_installer_payload(directory.path());
    let installer = release_script("install-macos.sh");
    let installed = Command::new(&installer)
        .args(["install"])
        .arg(&root)
        .args(["501", "alice"])
        .arg(&payload)
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .output()
        .unwrap();
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let broker_plist = root.join("Library/LaunchAgents/com.bloom.broker.501.plist");
    let signer_plist = root.join("Library/LaunchAgents/com.bloom.signer.501.plist");
    for plist in [&broker_plist, &signer_plist] {
        let source = fs::read_to_string(plist).unwrap();
        assert!(!source.contains("@BLOOM_"));
        assert!(source.contains("BLOOM_AUDIT_CHECKPOINT_DIR"));
        assert_eq!(
            fs::metadata(plist).unwrap().permissions().mode() & 0o777,
            0o600
        );
        if cfg!(target_os = "macos") {
            assert!(
                Command::new("plutil")
                    .args(["-lint"])
                    .arg(plist)
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }
    assert_eq!(
        fs::metadata(
            root.join("Library/Application Support/BloomTriad/logins/501/signer/audit-checkpoints")
        )
        .unwrap()
        .permissions()
        .mode()
            & 0o777,
        0o700
    );
    assert!(
        Command::new(&installer)
            .args(["uninstall"])
            .arg(&root)
            .args(["501", "delete-bloom-login-501"])
            .status()
            .unwrap()
            .success()
    );
    assert!(!broker_plist.exists());
    assert!(!signer_plist.exists());
}
