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

fn assert_ordered(source: &str, needles: &[&str]) {
    let mut offset = 0;
    for needle in needles {
        let position = source[offset..]
            .find(needle)
            .unwrap_or_else(|| panic!("missing ordered source fragment {needle}"));
        offset += position + needle.len();
    }
}

#[test]
fn broker_launchdaemon_selects_owned_unix_sockets_and_direct_ceremony_bind() {
    let source = fs::read_to_string(
        workspace().join("packaging/triad/macos/launchdaemons/com.bloom.broker.plist.in"),
    )
    .expect("read Broker LaunchDaemon source");

    assert!(source.contains("<key>UserName</key>"));
    assert!(source.contains("@BLOOM_BROKER_USER@"));
    assert!(source.contains("<key>GroupName</key>\n  <string>@BLOOM_REVOKE_GROUP@</string>"));
    assert!(source.contains("<key>InitGroups</key>\n  <true/>"));
    assert!(source.contains("<key>BLOOM_BROKER_SOCKET</key>"));
    assert!(source.contains("@BLOOM_BROKER_SOCKET@"));
    assert!(source.contains("<key>BLOOM_BROKER_CONTROL_SOCKET</key>"));
    assert!(source.contains("@BLOOM_BROKER_CONTROL_SOCKET@"));
    assert!(!source.contains("<key>Sockets</key>"));
    assert!(!source.contains("SockPath"));
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
    assert!(source.contains("<key>BLOOM_BROKER_STARTUP_STATUS</key>"));
    assert!(source.contains("@BLOOM_BROKER_STARTUP_STATUS@"));
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
    assert!(source.contains("<key>GroupName</key>\n  <string>@BLOOM_REVOKE_GROUP@</string>"));
    assert!(source.contains("<key>InitGroups</key>\n  <true/>"));
    assert!(source.contains("<key>BLOOM_SIGNER_SOCKET</key>"));
    assert!(source.contains("@BLOOM_SIGNER_SOCKET@"));
    assert!(source.contains("<key>BLOOM_SIGNER_CONTROL_SOCKET</key>"));
    assert!(source.contains("@BLOOM_SIGNER_CONTROL_SOCKET@"));
    assert!(source.contains("<key>BLOOM_SESSION_SOCKET</key>"));
    assert!(source.contains("@BLOOM_SESSION_SOCKET@"));
    assert!(!source.contains("<key>Sockets</key>"));
    assert!(!source.contains("SockPath"));
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
        ".enrollment-templates.XXXXXX",
        "$payload/installer/macos/config/$public_template",
        "\"$template_staging\"",
        "config_source=\"$generated_material\"",
        "generated_macos_enrollment",
        "dsmemberutil flushcache",
        "require_effective_group_member",
        "chown \"$broker_user:$machine_broker_group\" \"$runtime_root/machine-broker\"",
        "chown \"$signer_user:$broker_signer_group\" \"$runtime_root/broker-signer\"",
        "$runtime_root/revoke/broker",
        "$runtime_root/revoke/signer",
    ] {
        assert!(
            source.contains(required),
            "live installer is missing fail-closed input {required}"
        );
    }
    for empty_recovery in [
        r#"[[ -e "$upgrade_transaction" ]] || return 0"#,
        r#"[[ -e "$transaction_root" ]] || return 0"#,
        r#"[[ -e "$rotation_transaction" ]] || return 0"#,
        r#"[[ -e "$uninstall_root" ]] || return 0"#,
        r#"[[ -e "$retained_root" ]] || return 0"#,
    ] {
        assert!(
            source.contains(empty_recovery),
            "a clean first install must treat absent recovery state as success"
        );
    }
    for bash3_unsafe_empty_array in [
        r#""${pending_transactions[@]}""#,
        r#""${abandoned_rotation_staging[@]}""#,
        r#""${abandoned_uninstall_staging[@]}""#,
        r#""${transactions[@]}""#,
        r#""${retained_records[@]}""#,
        r#""${installed_enrollment_files[@]}""#,
    ] {
        assert!(
            !source.contains(bash3_unsafe_empty_array),
            "macOS Bash 3.2 must not expand a possibly empty array under nounset"
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
        "health_check_upgrade_brokers_sequentially",
        "active_session_uids",
        "launchctl bootstrap system \"$broker_plist\"",
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

    let sequential = source
        .split("health_check_upgrade_brokers_sequentially() {")
        .nth(1)
        .unwrap()
        .split("\n}\n\nrestore_upgrade_files()")
        .next()
        .unwrap();
    assert_ordered(
        sequential,
        &[
            "active_session_uids",
            "launchctl bootstrap system \"$broker_plist\"",
            "--triad-health-check",
            "launchctl bootout \"system/com.bloom.broker.$enrolled_uid\"",
        ],
    );

    let activation = source
        .split("activate_upgrade_transaction() {")
        .nth(1)
        .unwrap()
        .split("\n}\n\ninstall_immutable_release()")
        .next()
        .unwrap();
    assert_ordered(
        activation,
        &[
            "restore_upgrade_jobs session",
            "restore_upgrade_jobs signer",
            "health_check_upgrade_brokers_sequentially \"$new_digest\"",
            "restore_upgrade_jobs broker",
            "write_upgrade_phase committed",
        ],
    );

    let rollback = source
        .split("rollback_upgrade() {")
        .nth(1)
        .unwrap()
        .split("\n}\n\nrecover_interrupted_upgrade()")
        .next()
        .unwrap();
    assert_ordered(
        rollback,
        &[
            "restore_upgrade_jobs session",
            "restore_upgrade_jobs signer",
            "health_check_upgrade_brokers_sequentially \"$old_digest\"",
            "restore_upgrade_jobs broker",
        ],
    );
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
        assert!(source.contains("macOS Unix-principal bundle contains private key material"));
        assert!(source.contains("private_key_seed_hex|signing_seed_hex"));
        assert!(source.contains("private identity-shaped file"));
        assert!(source.contains("verify-macos-conformance.sh"));
    }
    let builder =
        fs::read_to_string(workspace().join("packaging/triad/release/build-bundle.sh")).unwrap();
    assert!(builder.contains("BLOOM_MACOS_CONFORMANCE_KEY_SHA256"));
    assert!(builder.contains("BLOOM_MACOS_CONFORMANCE_REPORT"));
    let verifier =
        fs::read_to_string(workspace().join("packaging/triad/release/verify-macos-conformance.sh"))
            .unwrap();
    assert!(verifier.contains("bloom.macos-unix-conformance.1"));
    assert!(verifier.contains("installed_ac_01_35"));
    assert!(verifier.contains("two_login_lifecycle"));
    assert!(verifier.contains("release_subject_digest"));
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
    assert!(source.contains("foreign_or_unverifiable_process"));
    assert!(source.contains("Bloom Broker startup failed: a foreign or unverifiable process"));
    assert!(source.contains("Signer opened a forbidden IPv6 loopback TCP connection"));
    assert!(source.contains("assert_udp_blocked"));
    assert!(source.contains("forbidden non-loopback IPv4 TCP connection"));
    assert!(source.contains("unrelated local UID opened protected Unix endpoint"));
    assert!(source.contains("Machine login opened the Broker-to-Signer data endpoint"));
    assert!(source.contains("assert_principal_cannot_replace"));
    assert!(source.contains("run_reinstall_with_substitution"));
    assert!(source.contains("installer accepted $substitution edge-manifest tampering"));
    assert!(source.contains("task-access-probe"));
    assert!(source.contains("Machine login sampled"));
    assert!(source.contains("session sentinel did not reject an unauthorized login-UID peer"));
    assert!(source.contains("services did not drain after the login-session sentinel disappeared"));
    assert!(source.contains("Broker retained the ceremony listener after session logout"));
    assert!(source.contains("launchctl bootstrap \"gui/$login_uid\" \"$session_plist\""));
    assert!(source.contains("run-installed-acceptance.sh"));
    assert!(source.contains("BLOOM_MACOS_INSTALLED_ACCEPTANCE_MAIN_ROOT"));
    assert!(
        !source.contains("touch \"$marker\"")
            && !source.contains("install -m 0600 /dev/null \"$marker\""),
        "the repository must not self-authorize a host as disposable"
    );

    let two_login =
        fs::read_to_string(workspace().join("packaging/triad/macos/w0/run-two-login.sh")).unwrap();
    assert!(two_login.contains("active GUI domains for both selected users"));
    assert!(two_login.contains("another_login_session"));
    assert!(two_login.contains("second Broker opened a fallback TCP listener"));
    assert!(two_login.contains("launchctl bootout \"gui/$login_uid_b\""));
    assert!(two_login.contains("through failure-only KeepAlive"));
    assert!(two_login.contains("before any new Machine request"));
    assert!(two_login.contains("two_login_lifecycle"));
    assert!(two_login.contains("failing upgrade unexpectedly committed"));
    assert!(two_login.contains("two-login upgrade rollback split the installed release"));
    assert!(two_login.contains("mui_09.pass"));
    assert!(two_login.contains("macos-conformance-subject.sh"));
    assert!(
        !two_login.contains("touch \"$marker\"")
            && !two_login.contains("install -m 0600 /dev/null \"$marker\""),
        "the two-login harness must not self-authorize a host as disposable"
    );

    let installed_acceptance = fs::read_to_string(
        workspace().join("packaging/triad/macos/w0/run-installed-acceptance.sh"),
    )
    .unwrap();
    assert!(installed_acceptance.contains("installed_ac_01_35"));
    assert!(installed_acceptance.contains("mui_01"));
    assert!(installed_acceptance.contains("mui_11"));
    assert!(installed_acceptance.contains("mui_12"));
    assert!(installed_acceptance.contains("TeamIdentifier="));
    assert!(installed_acceptance.contains("release gate emitted a production macOS claim"));
    assert!(installed_acceptance.contains("BLOOM_ACCEPTANCE_BUNDLE_ROOT"));
    assert!(installed_acceptance.contains("assert_installed_process bloom-broker"));
    assert!(installed_acceptance.contains("assert_installed_process bloom-signer"));
    assert!(installed_acceptance.contains("-p bloom-triad-protocol"));
    assert!(installed_acceptance.contains("--workspace"));
    assert!(
        !installed_acceptance.contains("touch \"$marker\"")
            && !installed_acceptance.contains("install -m 0600 /dev/null \"$marker\""),
        "the installed-acceptance harness must not self-authorize a host as disposable"
    );

    let ci = fs::read_to_string(workspace().join(".github/workflows/ci.yml")).unwrap();
    assert!(ci.contains("macos_unix_principal_disposable_w0"));
    assert!(ci.contains("github.event_name == 'workflow_dispatch'"));
    assert!(ci.contains("github.ref_name == 'triad-architecture'"));
    assert!(ci.contains("uses: ./.github/workflows/macos-unix-w0.yml"));

    let workflow =
        fs::read_to_string(workspace().join(".github/workflows/macos-unix-w0.yml")).unwrap();
    assert!(workflow.contains("workflow_call:"));

    let two_login_workflow =
        fs::read_to_string(workspace().join(".github/workflows/macos-two-login-w0.yml")).unwrap();
    assert!(two_login_workflow.contains("bloom-two-login-disposable"));
    assert!(two_login_workflow.contains("test \"$(id -u)\" !="));
    assert!(two_login_workflow.contains("failing-broker.c"));
    assert!(two_login_workflow.contains("run-two-login.sh"));
    assert!(two_login_workflow.contains("macos-two-login-evidence/*.pass"));
}
