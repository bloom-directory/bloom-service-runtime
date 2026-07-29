use std::{fs, path::Path};

#[test]
fn broker_launchagent_owns_every_listener_and_retries_fatal_startup() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("service activation crate is inside the workspace");
    let source = fs::read_to_string(
        workspace.join("packaging/triad/macos/launchagents/com.bloom.broker.plist.in"),
    )
    .expect("read Broker LaunchAgent source");

    for socket_name in ["broker", "broker-control", "broker-ceremony"] {
        assert!(
            source.contains(&format!("<key>{socket_name}</key>")),
            "launchd does not own {socket_name}"
        );
    }
    for canonical_value in [
        "<string>127.0.0.1</string>",
        "<integer>18734</integer>",
        "<string>IPv4</string>",
        "<string>TCP</string>",
    ] {
        assert!(
            source.contains(canonical_value),
            "canonical listener is missing {canonical_value}"
        );
    }
    assert!(
        source.contains("<key>KeepAlive</key>")
            && source.contains("<key>SuccessfulExit</key>")
            && source.contains("<false/>")
            && source.contains("<key>ThrottleInterval</key>"),
        "fatal Broker startup is not configured for throttled launchd retry"
    );
    assert!(
        !source.contains("18735") && !source.contains("SO_REUSE"),
        "LaunchAgent source contains a fallback or address-reuse path"
    );
}

#[test]
fn sandbox_groups_form_only_the_two_authorized_edges() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("service activation crate is inside the workspace");
    let entitlements = workspace.join("packaging/triad/macos/entitlements");
    let machine = fs::read_to_string(entitlements.join("bloom-machine.entitlements.in")).unwrap();
    let broker = fs::read_to_string(entitlements.join("bloom-broker.entitlements.in")).unwrap();
    let signer =
        fs::read_to_string(entitlements.join("bloom-signer-local.entitlements.in")).unwrap();

    for source in [&machine, &broker, &signer] {
        assert!(
            source.contains("<key>com.apple.security.app-sandbox</key>")
                && source.contains("<true/>"),
            "every production role must carry a mandatory sandbox identity"
        );
        assert!(
            !source.contains("get-task-allow"),
            "production entitlements must not permit debugger attachment"
        );
    }

    let machine_broker = "@TEAM_ID@.bloom.machine-broker";
    let broker_signer = "@TEAM_ID@.bloom.broker-signer";
    assert!(machine.contains(machine_broker));
    assert!(!machine.contains(broker_signer));
    assert!(broker.contains(machine_broker));
    assert!(broker.contains(broker_signer));
    assert!(!signer.contains(machine_broker));
    assert!(signer.contains(broker_signer));
    assert!(
        !signer.contains("com.apple.security.network"),
        "local Signer must have no network entitlement"
    );
}

#[test]
fn macos_packaging_pins_the_platform_managed_time_source() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("service activation crate is inside the workspace");
    let readme = fs::read_to_string(workspace.join("packaging/triad/macos/README.md")).unwrap();
    assert!(readme.contains("trusted_time_source"));
    assert!(readme.contains("macos-managed-timed"));
    assert!(readme.contains("Peer-supplied time"));
}
