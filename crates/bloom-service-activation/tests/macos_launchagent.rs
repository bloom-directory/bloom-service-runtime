use std::{
    fs,
    path::{Path, PathBuf},
};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("service activation crate is inside the workspace")
        .to_path_buf()
}

#[test]
fn broker_launchdaemon_uses_distinct_uid_gid_sockets_and_direct_ceremony_bind() {
    let source = fs::read_to_string(
        workspace().join("packaging/triad/macos/launchdaemons/com.bloom.broker.plist.in"),
    )
    .expect("read Broker LaunchDaemon source");

    assert!(source.contains("<key>UserName</key>"));
    assert!(source.contains("@BLOOM_BROKER_USER@"));
    for socket_name in ["broker", "broker-control"] {
        assert!(
            source.contains(&format!("<key>{socket_name}</key>")),
            "launchd does not own {socket_name}"
        );
    }
    for ownership in [
        "@BLOOM_BROKER_UID@",
        "@MACHINE_BROKER_GID@",
        "@REVOKE_GID@",
        "<integer>432</integer>",
    ] {
        assert!(
            source.contains(ownership),
            "Broker socket ownership is missing {ownership}"
        );
    }
    assert!(
        !source.contains("broker-ceremony")
            && !source.contains("18734")
            && !source.contains("SockNodeName"),
        "Unix-principal Broker must bind the canonical TCP listener itself"
    );
    assert!(
        source.contains("<key>KeepAlive</key>")
            && source.contains("<key>SuccessfulExit</key>")
            && source.contains("<false/>")
            && source.contains("<key>ThrottleInterval</key>"),
        "fatal Broker startup is not configured for throttled launchd retry"
    );
    assert!(source.contains("<key>Core</key>\n    <integer>0</integer>"));
}

#[test]
fn signer_launchdaemon_exposes_only_broker_and_revoke_group_edges() {
    let source = fs::read_to_string(
        workspace().join("packaging/triad/macos/launchdaemons/com.bloom.signer.plist.in"),
    )
    .expect("read Signer LaunchDaemon source");

    assert!(source.contains("<key>UserName</key>"));
    assert!(source.contains("@BLOOM_SIGNER_USER@"));
    assert!(source.contains("@BLOOM_SIGNER_UID@"));
    assert!(source.contains("@BROKER_SIGNER_GID@"));
    assert!(source.contains("@REVOKE_GID@"));
    assert!(source.contains("<key>BLOOM_SESSION_SOCKET</key>"));
    assert!(source.contains("@BLOOM_SESSION_SOCKET@"));
    assert!(!source.contains("@MACHINE_BROKER_GID@"));
    assert!(!source.contains("com.apple.security.network"));
    assert!(!source.contains("broker-ceremony"));
}

#[test]
fn session_agent_has_no_service_authority_and_stops_with_the_login_domain() {
    let source = fs::read_to_string(
        workspace().join("packaging/triad/macos/launchagents/com.bloom.session.plist.in"),
    )
    .expect("read session LaunchAgent source");

    assert!(source.contains("@BLOOM_MACHINE_BINARY@"));
    assert!(source.contains("<string>--session-sentinel</string>"));
    assert!(source.contains("BLOOM_CONFIG_ROOT"));
    assert!(source.contains("/private/var/run/bloom"));
    assert!(source.contains("<string>Aqua</string>"));
    assert!(!source.contains("UserName"));
    assert!(!source.contains("Sockets"));
    assert!(!source.contains("BLOOM_BROKER_CONFIG"));
    assert!(!source.contains("BLOOM_SIGNER_CONFIG"));
}

#[test]
fn broker_requires_the_authenticated_session_socket_before_ceremonies() {
    let source = fs::read_to_string(
        workspace().join("packaging/triad/macos/launchdaemons/com.bloom.broker.plist.in"),
    )
    .expect("read Broker LaunchDaemon source");
    assert!(source.contains("<key>BLOOM_SESSION_SOCKET</key>"));
    assert!(source.contains("@BLOOM_SESSION_SOCKET@"));

    let machine = fs::read_to_string(workspace().join("crates/bloom/src/session_sentinel.rs"))
        .expect("read Machine session sentinel");
    assert!(machine.contains("authenticate_server"));
    assert!(machine.contains("bloom-session"));
    assert!(machine.contains("remove_owned_stale_socket"));
    assert!(machine.contains("session_socket_gid"));

    let cli = fs::read_to_string(workspace().join("crates/bloom/src/main.rs")).unwrap();
    assert!(cli.contains("/Library/Application Support/BloomTriad/enrollments/"));
    assert!(cli.contains("/private/var/run/bloom/{uid}/machine-broker/broker.sock"));
}

#[test]
fn macos_packaging_pins_platform_time_checkpoint_and_future_rootless_separation() {
    let readme = fs::read_to_string(workspace().join("packaging/triad/macos/README.md")).unwrap();
    assert!(readme.contains("Unix-principal"));
    assert!(readme.contains("macos-rootless-code-identity"));
    assert!(readme.contains("future target"));
    assert!(readme.contains("checkpoint"));
    assert!(readme.contains("disposable macOS W0"));
}

#[test]
fn pf_source_denies_broker_and_signer_by_numeric_effective_uid() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/macos/pf/com.bloom.login.conf.in"))
            .expect("read packet-filter source");
    assert!(source.contains("user @BLOOM_SIGNER_UID@"));
    assert!(source.contains("user @BLOOM_BROKER_UID@"));
    assert!(source.contains("block return out quick"));
    assert!(!source.contains("0.0.0.0/0"));
    assert!(!source.contains("::/0"));
}

#[test]
fn root_pf_monitor_has_no_rpc_or_custody_surface_and_services_require_its_attestation() {
    let plist = fs::read_to_string(
        workspace().join("packaging/triad/macos/launchdaemons/com.bloom.containment.plist.in"),
    )
    .unwrap();
    assert!(plist.contains("<string>root</string>"));
    assert!(plist.contains("--triad-pf-monitor-once"));
    assert!(plist.contains("<key>StartInterval</key>"));
    assert!(!plist.contains("<key>Sockets</key>"));

    let monitor = fs::read_to_string(workspace().join("crates/bloom/src/pf_monitor.rs")).unwrap();
    assert!(monitor.contains("/sbin/pfctl"));
    assert!(monitor.contains("bloom.macos-network-containment.1"));
    assert!(monitor.contains("status.json"));
    assert!(!monitor.contains("signing_seed"));

    for config in ["broker.json.in", "signer.json.in"] {
        let source = fs::read_to_string(
            workspace()
                .join("packaging/triad/macos/config")
                .join(config),
        )
        .unwrap();
        assert!(source.contains("\"network_containment\""));
        assert!(source.contains("@BLOOM_CONTAINMENT_STATUS@"));
    }
}

#[test]
fn live_installer_provisions_fail_closed_directory_service_records() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/release/install-macos.sh")).unwrap();
    for required in [
        "require_live_macos_root",
        "acquire_installer_lock",
        "next_directory_id",
        "refusing to adopt pre-existing user",
        "refusing to adopt pre-existing group",
        "AuthenticationAuthority \";DisabledUser;\"",
        "rollback_provisioning",
        "verify_existing_enrollment",
        "BLOOM_RELEASE_PUBLIC_KEY",
        "pinned release key must be root-owned",
        "--triad-render-macos-enrollment",
        "config_source=\"$generated_material\"",
    ] {
        assert!(
            source.contains(required),
            "live installer is missing fail-closed input {required}"
        );
    }
    assert!(!source.contains("macos-rootless-code-identity"));
    assert!(!source.contains("com.apple.security.application-groups"));
}

#[test]
fn macos_upgrade_is_global_journaled_and_health_checked() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/release/install-macos.sh")).unwrap();
    for required in [
        "bloom.macos-upgrade-transaction.1",
        "recover_interrupted_upgrade",
        "prepare_upgrade_transaction",
        "activate_upgrade_transaction",
        "rollback_upgrade",
        "installed enrollments do not share one complete release",
        "stop_upgrade_jobs",
        "restore_upgrade_files",
        "--triad-health-check",
        "install_immutable_release",
        "bloom.macos-enrollment-transaction.1",
        "recover_pending_enrollments",
        "rollback_enrollment_transaction",
        "publish_enrollment_active",
        "stale Bloom installer lock",
        "kill -0 \"$lock_pid\"",
    ] {
        assert!(
            source.contains(required),
            "macOS installer is missing upgrade invariant {required}"
        );
    }
    assert!(!source.contains(
        "macOS atomic release upgrade is not enabled until rollback health checks are implemented"
    ));
}

#[test]
fn macos_config_rotation_is_journaled_verified_and_recoverable() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/release/install-macos.sh")).unwrap();
    for required in [
        "bloom.macos-config-rotation.1",
        "bloom.macos-transport-rotation.1",
        ".rotation-transaction.new.$$",
        "verify_config_rotation",
        "prepare_rotation",
        "activate_rotation",
        "rollback_rotation",
        "recover_interrupted_rotation",
        "config rotation may not change",
        "atomic_copy_preserving_metadata",
        "health_check_enrollment",
        "prepare_transport_rotation",
        "swap_transport_rotation_tree",
        "--triad-render-macos-identity-rotation",
    ] {
        assert!(
            source.contains(required),
            "macOS installer is missing config-rotation invariant {required}"
        );
    }
}

#[test]
fn macos_permanent_uninstall_is_forward_recoverable() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/release/install-macos.sh")).unwrap();
    for required in [
        "bloom.macos-uninstall-transaction.2",
        "$uninstall_root/.new.$$",
        "prepare_uninstall_transaction",
        "execute_uninstall_transaction",
        "recover_interrupted_uninstalls",
        "state -string uninstalling",
        "delete_directory_record_if_exact",
        "custody state is not recoverable",
        "retain-bloom-login-$login_uid",
        "recover_retained_restores",
        "must be restored with its exact signed release",
    ] {
        assert!(
            source.contains(required),
            "macOS installer is missing uninstall invariant {required}"
        );
    }
}

#[test]
fn activating_enrollment_is_private_to_installer_health_and_session_bootstrap() {
    let machine = fs::read_to_string(workspace().join("crates/bloom/src/main.rs")).unwrap();
    assert!(machine.contains("allow_activating"));
    assert!(machine.contains("installed Bloom enrollment is not active"));
    let sentinel =
        fs::read_to_string(workspace().join("crates/bloom/src/session_sentinel.rs")).unwrap();
    assert!(sentinel.contains("Some(\"activating\" | \"active\")"));
    let installer =
        fs::read_to_string(workspace().join("packaging/triad/release/install-macos.sh")).unwrap();
    let health = installer.find("health_check_enrollment").unwrap();
    let publish = installer.rfind("publish_enrollment_active").unwrap();
    assert!(health < publish);
}

#[test]
fn production_macos_bundle_forbids_archived_private_identity_material() {
    for script in ["build-bundle.sh", "verify-bundle.sh"] {
        let source =
            fs::read_to_string(workspace().join("packaging/triad/release").join(script)).unwrap();
        assert!(source.contains("production macOS bundle contains private key material"));
        assert!(source.contains("private_key_seed_hex|signing_seed_hex"));
        assert!(source.contains("private identity-shaped file"));
    }
    let templates = workspace().join("packaging/triad/macos/config");
    for entry in fs::read_dir(templates).unwrap() {
        let path = entry.unwrap().path();
        let bytes = fs::read_to_string(&path).unwrap();
        for line in bytes.lines().filter(|line| line.contains("seed_hex")) {
            assert!(
                line.contains('@'),
                "{} contains a concrete private seed",
                path.display()
            );
        }
    }
}

#[test]
fn privileged_w0_harness_requires_an_external_disposable_host_marker() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/macos/w0/run-disposable.sh")).unwrap();
    assert!(source.contains("BLOOM_RUN_MACOS_UNIX_W0"));
    assert!(source.contains("/private/var/db/bloom-w0-disposable-host"));
    assert!(source.contains("bloom-macos-unix-w0-disposable-v1"));
    assert!(source.contains("macos-unix-principals-w0"));
    assert!(source.contains("FAILING_UPGRADE_PAYLOAD"));
    assert!(source.contains("kill -9 \"$interrupted_pid\""));
    assert!(source.contains("upgrade-transaction/phase"));
    assert!(source.contains("/usr/bin/nc -l 127.0.0.1 18734"));
    assert!(source.contains("no fallback port will be used"));
    assert!(source.contains("Broker opened a fallback TCP listener"));
    assert!(source.contains("Signer opened a forbidden IPv6 loopback TCP connection"));
    assert!(source.contains("assert_udp_blocked"));
    assert!(source.contains("forbidden non-loopback IPv4 TCP connection"));
    assert!(
        !source.contains("touch \"$marker\"")
            && !source.contains("install -m 0600 /dev/null \"$marker\""),
        "the repository must not self-authorize a host as disposable"
    );
}
