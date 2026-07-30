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
fn privileged_w0_harness_requires_an_external_disposable_host_marker() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/macos/w0/run-disposable.sh")).unwrap();
    assert!(source.contains("BLOOM_RUN_MACOS_UNIX_W0"));
    assert!(source.contains("/private/var/db/bloom-w0-disposable-host"));
    assert!(source.contains("bloom-macos-unix-w0-disposable-v1"));
    assert!(source.contains("macos-unix-principals-w0"));
    assert!(
        !source.contains("touch \"$marker\"")
            && !source.contains("install -m 0600 /dev/null \"$marker\""),
        "the repository must not self-authorize a host as disposable"
    );
}
