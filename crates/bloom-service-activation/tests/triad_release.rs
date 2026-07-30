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
        let version = if binary == "bloom" { "0.1.3" } else { "0.1.0" };
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
        "machine-identity.json",
        "broker-identity.json",
        "signer-identity.json",
        "revoke-identity.json",
        "session-identity.json",
        "installer-identity.json",
        "provenance-catalog.json",
    ] {
        fs::write(payload.join("config").join(config), b"{}").unwrap();
    }
    fs::write(
        payload.join("config/edge-manifest.json"),
        br#"{
  "machine_uid": @LOGIN_UID@,
  "broker_uid": @BLOOM_BROKER_UID@,
  "signer_uid": @BLOOM_SIGNER_UID@,
  "session_socket_gid": @SESSION_SOCKET_GID@
}"#,
    )
    .unwrap();
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

fn macos_subject(payload: &Path) -> std::process::Output {
    Command::new(release_script("macos-conformance-subject.sh"))
        .arg(payload)
        .output()
        .unwrap()
}

fn stage_macos_install(installer: &Path, root: &Path, payload: &Path) -> std::process::Output {
    Command::new(installer)
        .args(["install"])
        .arg(root)
        .args(["501", "alice"])
        .arg(payload)
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .env("BLOOM_MACOS_BROKER_UID", "250501")
        .env("BLOOM_MACOS_SIGNER_UID", "250502")
        .env("BLOOM_MACOS_BROKER_GID", "260499")
        .env("BLOOM_MACOS_SIGNER_GID", "260500")
        .env("BLOOM_MACOS_MACHINE_BROKER_GID", "260501")
        .env("BLOOM_MACOS_BROKER_SIGNER_GID", "260502")
        .env("BLOOM_MACOS_REVOKE_GID", "260503")
        .env("BLOOM_RELEASE_DIGEST", "11".repeat(32))
        .output()
        .unwrap()
}

#[test]
fn acceptance_rerun_is_bound_to_the_verified_bundle_when_present() {
    let Some(bundle) = std::env::var_os("BLOOM_ACCEPTANCE_BUNDLE_ROOT") else {
        return;
    };
    let bundle = PathBuf::from(bundle);
    let expected_claim = if std::env::var("BLOOM_ALLOW_TEST_UNCLAIMED").as_deref() == Ok("true") {
        "test-unclaimed"
    } else if std::env::var("BLOOM_ALLOW_MACOS_UNIX_W0").as_deref() == Ok("true") {
        "macos-unix-principals-w0"
    } else if cfg!(target_os = "macos") {
        "macos-unix-principals"
    } else {
        "linux"
    };
    assert_eq!(
        fs::read_to_string(bundle.join("PLATFORM_CLAIM"))
            .unwrap()
            .trim(),
        expected_claim
    );
    for (binary, expected_version) in [
        ("bloom", format!("bloom {}", env!("CARGO_PKG_VERSION"))),
        ("bloom-broker", "bloom-broker 0.1.0".to_owned()),
        ("bloom-signer", "bloom-signer 0.1.0".to_owned()),
    ] {
        let output = Command::new(bundle.join("bin").join(binary))
            .arg("--version")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            expected_version
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
fn macos_conformance_subject_excludes_only_the_claim_and_signature_envelope() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("payload");
    fs::create_dir_all(payload.join("installer/macos")).unwrap();
    fs::write(payload.join("bin"), b"machine-broker-signer").unwrap();
    fs::write(payload.join("installer/macos/profile"), b"uid-boundary").unwrap();
    fs::write(
        payload.join("PLATFORM_CLAIM"),
        b"macos-unix-principals-w0\n",
    )
    .unwrap();
    let baseline = macos_subject(&payload);
    assert!(
        baseline.status.success(),
        "{}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    let baseline = String::from_utf8(baseline.stdout).unwrap();

    for (name, bytes) in [
        ("PLATFORM_CLAIM", b"macos-unix-principals\n".as_slice()),
        ("MACOS_CONFORMANCE_REPORT.json", b"report".as_slice()),
        ("MACOS_CONFORMANCE_REPORT.sig", b"signature".as_slice()),
        ("MACOS_CONFORMANCE_REPORT.pub", b"public-key".as_slice()),
        ("RELEASE_PUBLIC_KEY.pem", b"release-key".as_slice()),
        ("RELEASE_SIGNATURE", b"release-signature".as_slice()),
        ("SHA256SUMS", b"release-manifest".as_slice()),
    ] {
        fs::write(payload.join(name), bytes).unwrap();
    }
    let envelope_changed = macos_subject(&payload);
    assert!(envelope_changed.status.success());
    assert_eq!(
        baseline,
        String::from_utf8(envelope_changed.stdout).unwrap()
    );

    fs::write(payload.join("installer/macos/profile"), b"changed-boundary").unwrap();
    let security_input_changed = macos_subject(&payload);
    assert!(security_input_changed.status.success());
    assert_ne!(
        baseline,
        String::from_utf8(security_input_changed.stdout).unwrap()
    );

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("profile", payload.join("installer/macos/substitution"))
            .unwrap();
        let substituted = macos_subject(&payload);
        assert!(!substituted.status.success());
        assert!(String::from_utf8_lossy(&substituted.stderr).contains("contains a symlink"));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_production_conformance_report_is_signed_complete_and_subject_bound() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("payload");
    fs::create_dir_all(payload.join("installer/release")).unwrap();
    fs::write(payload.join("security-input"), b"exact-tested-content").unwrap();
    fs::write(
        payload.join("SOURCE_REVISIONS"),
        b"BLOOM_BROKER_SHA=2222222\nBLOOM_MACHINE_SHA=1111111\nBLOOM_SIGNER_SHA=3333333\n",
    )
    .unwrap();
    for script in [
        "macos-conformance-subject.sh",
        "sign-macos-conformance-report.sh",
        "verify-macos-conformance.sh",
    ] {
        let destination = payload.join("installer/release").join(script);
        fs::copy(release_script(script), &destination).unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let subject = macos_subject(&payload);
    assert!(subject.status.success());
    let subject = String::from_utf8(subject.stdout).unwrap();
    let private_key = directory.path().join("conformance.pem");
    let public_key = payload.join("MACOS_CONFORMANCE_REPORT.pub");
    let evidence = directory.path().join("evidence");
    fs::create_dir(&evidence).unwrap();
    for criterion in [
        "mui_01",
        "mui_02",
        "mui_03",
        "mui_04",
        "mui_05",
        "mui_06",
        "mui_07",
        "mui_08",
        "mui_09",
        "mui_10",
        "mui_11",
        "mui_12",
        "installed_ac_01_35",
        "negative_access",
    ] {
        fs::write(evidence.join(format!("{criterion}.pass")), &subject).unwrap();
    }
    assert!(
        Command::new("openssl")
            .args(["genpkey", "-algorithm", "ED25519", "-out"])
            .arg(&private_key)
            .status()
            .unwrap()
            .success()
    );
    let missing = Command::new(release_script("sign-macos-conformance-report.sh"))
        .arg(&payload)
        .arg("44".repeat(32))
        .args(["2026-07-30T12:00:00Z", "25G86", "arm64", "w0-test-report"])
        .arg(&evidence)
        .arg(&private_key)
        .arg(&payload)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("two_login_lifecycle"));
    fs::write(evidence.join("two_login_lifecycle.pass"), &subject).unwrap();
    let signed = Command::new(release_script("sign-macos-conformance-report.sh"))
        .arg(&payload)
        .arg("44".repeat(32))
        .args(["2026-07-30T12:00:00Z", "25G86", "arm64", "w0-test-report"])
        .arg(&evidence)
        .arg(&private_key)
        .arg(&payload)
        .output()
        .unwrap();
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let key_digest = Command::new("shasum")
        .args(["-a", "256"])
        .arg(&public_key)
        .output()
        .unwrap();
    assert!(key_digest.status.success());
    let key_digest = String::from_utf8(key_digest.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let verified = Command::new(release_script("verify-macos-conformance.sh"))
        .arg(&payload)
        .arg(&key_digest)
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );

    fs::write(payload.join("security-input"), b"post-test-change").unwrap();
    let changed = Command::new(release_script("verify-macos-conformance.sh"))
        .arg(&payload)
        .arg(&key_digest)
        .output()
        .unwrap();
    assert!(!changed.status.success());
    assert!(
        String::from_utf8_lossy(&changed.stderr).contains("does not bind this release subject")
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
fn macos_installer_stages_unix_principals_launchdaemons_and_confirmed_uninstall() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    let payload = make_installer_payload(directory.path());
    let installer = release_script("install-macos.sh");
    let installed = stage_macos_install(&installer, &root, &payload);
    assert!(
        installed.status.success(),
        "status: {}; stderr: {}",
        installed.status,
        String::from_utf8_lossy(&installed.stderr)
    );
    let broker_plist = root.join("Library/LaunchDaemons/com.bloom.broker.501.plist");
    let signer_plist = root.join("Library/LaunchDaemons/com.bloom.signer.501.plist");
    for plist in [&broker_plist, &signer_plist] {
        let source = fs::read_to_string(plist).unwrap();
        assert!(!source.contains("@BLOOM_"));
        assert!(source.contains("BLOOM_AUDIT_CHECKPOINT_DIR"));
        assert!(source.contains("<key>UserName</key>"));
        assert_eq!(
            fs::metadata(plist).unwrap().permissions().mode() & 0o777,
            0o644
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
    let containment_plist = root.join("Library/LaunchDaemons/com.bloom.containment.plist");
    let containment_source = fs::read_to_string(&containment_plist).unwrap();
    assert!(containment_source.contains("--triad-pf-monitor-once"));
    assert!(!containment_source.contains("@BLOOM_"));
    assert_eq!(
        fs::metadata(&containment_plist)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(root.join("var/db/bloom/501/signer/audit-checkpoints"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let edge_manifest = fs::read_to_string(
        root.join("Library/Application Support/BloomTriad/config/501/edge-manifest.json"),
    )
    .unwrap();
    assert!(edge_manifest.contains("\"machine_uid\": 501"));
    assert!(edge_manifest.contains("\"broker_uid\": 250501"));
    assert!(edge_manifest.contains("\"signer_uid\": 250502"));
    assert!(edge_manifest.contains("\"session_socket_gid\": 260503"));
    let enrollment = fs::read_to_string(
        root.join("Library/Application Support/BloomTriad/enrollments/501.json"),
    )
    .unwrap();
    assert_eq!(
        fs::metadata(root.join("Library/Application Support/BloomTriad/enrollments/501.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert!(enrollment.contains("\"broker_gid\": 260499"));
    assert!(enrollment.contains("\"state\": \"activating\""));
    assert!(enrollment.contains("\"signer_gid\": 260500"));
    assert!(enrollment.contains("\"machine_broker_gid\": 260501"));
    assert!(enrollment.contains("\"broker_signer_gid\": 260502"));
    assert!(enrollment.contains("\"revoke_gid\": 260503"));
    let pf = fs::read_to_string(root.join("etc/pf.anchors/com.bloom.triad.501")).unwrap();
    assert!(pf.contains("user 250501"));
    assert!(pf.contains("user 250502"));
    assert!(
        root.join("usr/local/libexec/bloom/current/bloom-broker")
            .exists()
    );
    assert!(
        root.join("Library/LaunchAgents/com.bloom.session.plist")
            .exists()
    );
    assert_eq!(
        fs::metadata(root.join("Library/Application Support/BloomTriad/config/501/session"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for relative in [
        "machine/identity.json",
        "machine/revoke-identity.json",
        "installer/identity.json",
        "provenance-catalog.json",
    ] {
        assert!(
            root.join("Library/Application Support/BloomTriad/config/501")
                .join(relative)
                .is_file(),
            "macOS install omitted {relative}"
        );
    }

    let signer_checkpoints = root.join("var/db/bloom/501/signer/audit-checkpoints");
    let substituted = directory.path().join("substituted-checkpoints");
    fs::create_dir(&substituted).unwrap();
    fs::set_permissions(&substituted, fs::Permissions::from_mode(0o777)).unwrap();
    fs::remove_dir(&signer_checkpoints).unwrap();
    std::os::unix::fs::symlink(&substituted, &signer_checkpoints).unwrap();
    let rejected = stage_macos_install(&installer, &root, &payload);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("security directory"));
    assert_eq!(
        fs::metadata(&substituted).unwrap().permissions().mode() & 0o777,
        0o777,
        "rejected symlink substitution must not chmod the target"
    );
    fs::remove_file(&signer_checkpoints).unwrap();
    fs::create_dir(&signer_checkpoints).unwrap();

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
    assert!(
        root.join("usr/local/libexec/bloom/current/bloom-broker")
            .exists(),
        "per-login uninstall must not remove the shared release"
    );
}

#[test]
fn macos_installer_never_repairs_or_overwrites_a_digest_named_release() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    let payload = make_installer_payload(directory.path());
    let installer = release_script("install-macos.sh");
    assert!(
        stage_macos_install(&installer, &root, &payload)
            .status
            .success()
    );
    let installed_broker = root.join(format!(
        "usr/local/libexec/bloom/releases/{}/bloom-broker",
        "11".repeat(32)
    ));
    fs::write(&installed_broker, b"substituted").unwrap();

    let rejected = stage_macos_install(&installer, &root, &payload);
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("existing versioned Bloom release does not match its digest")
    );
    assert_eq!(fs::read(installed_broker).unwrap(), b"substituted");
}
