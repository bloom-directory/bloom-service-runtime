use std::{fs, path::Path};

fn packaging_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("service activation crate is inside the workspace")
        .join("packaging/triad/linux")
}

fn source(relative: &str) -> String {
    fs::read_to_string(packaging_root().join(relative))
        .unwrap_or_else(|error| panic!("read Linux packaging source {relative}: {error}"))
}

#[test]
fn systemd_owns_every_named_listener_without_a_fallback() {
    let sockets = [
        (
            "systemd/bloom-broker-rpc@.socket",
            "/run/bloom/%i/broker.sock",
            "FileDescriptorName=broker",
            "Service=bloom-broker@%i.service",
        ),
        (
            "systemd/bloom-broker-control@.socket",
            "/run/bloom/%i/broker-control.sock",
            "FileDescriptorName=broker-control",
            "Service=bloom-broker@%i.service",
        ),
        (
            "systemd/bloom-broker-ceremony@.socket",
            "ListenStream=127.0.0.1:18734",
            "FileDescriptorName=broker-ceremony",
            "Service=bloom-broker@%i.service",
        ),
        (
            "systemd/bloom-signer-rpc@.socket",
            "/run/bloom/%i/signer.sock",
            "FileDescriptorName=signer",
            "Service=bloom-signer@%i.service",
        ),
        (
            "systemd/bloom-signer-control@.socket",
            "/run/bloom/%i/signer-control.sock",
            "FileDescriptorName=signer-control",
            "Service=bloom-signer@%i.service",
        ),
    ];

    for (path, address, descriptor, service) in sockets {
        let unit = source(path);
        for required in [address, descriptor, service, "Accept=no"] {
            assert!(unit.contains(required), "{path} is missing {required}");
        }
        assert!(
            !unit.contains("18735")
                && !unit.contains("ReusePort=yes")
                && !unit.contains("Accept=yes"),
            "{path} contains a fallback or listener-sharing path"
        );
    }

    let ceremony = source("systemd/bloom-broker-ceremony@.socket");
    for required in [
        "FreeBind=no",
        "ReusePort=no",
        "IPAddressDeny=any",
        "IPAddressAllow=localhost",
    ] {
        assert!(
            ceremony.contains(required),
            "canonical listener is missing {required}"
        );
    }
}

#[test]
fn principals_groups_state_and_socket_acls_are_non_transitive() {
    let users = source("sysusers.d/bloom-login.conf.in");
    for required in [
        "u bloom-broker-@LOGIN_UID@",
        "u bloom-signer-@LOGIN_UID@",
        "m @LOGIN_USER@ bloom-machine-broker-@LOGIN_UID@",
        "m bloom-broker-@LOGIN_UID@ bloom-machine-broker-@LOGIN_UID@",
        "m bloom-broker-@LOGIN_UID@ bloom-broker-signer-@LOGIN_UID@",
        "m bloom-signer-@LOGIN_UID@ bloom-broker-signer-@LOGIN_UID@",
    ] {
        assert!(
            users.contains(required),
            "sysusers source is missing {required}"
        );
    }
    assert!(
        !users.contains("m @LOGIN_USER@ bloom-broker-signer-"),
        "Machine login principal must not join the Broker--Signer group"
    );

    let temporary_paths = source("tmpfiles.d/bloom-login.conf.in");
    for principal in ["broker", "signer"] {
        assert!(
            temporary_paths.contains(&format!(
                "d /var/lib/bloom/@LOGIN_UID@/{principal} 0700 bloom-{principal}-@LOGIN_UID@"
            )),
            "{principal} state root is not private to its effective principal"
        );
        assert!(
            temporary_paths.contains(&format!(
                "d /etc/bloom/@LOGIN_UID@/{principal} 0700 bloom-{principal}-@LOGIN_UID@"
            )),
            "{principal} configuration root is not private to its effective principal"
        );
    }

    let broker = source("systemd/bloom-broker-rpc@.socket");
    assert!(broker.contains("SocketGroup=bloom-machine-broker-%i"));
    assert!(broker.contains("SocketMode=0660"));
    let signer = source("systemd/bloom-signer-rpc@.socket");
    assert!(signer.contains("SocketGroup=bloom-broker-signer-%i"));
    assert!(signer.contains("SocketMode=0660"));
    for control in [
        "systemd/bloom-broker-control@.socket",
        "systemd/bloom-signer-control@.socket",
    ] {
        assert!(source(control).contains("SocketGroup=bloom-revoke-%i"));
    }
}

#[test]
fn service_sandboxes_remove_machine_and_network_authority() {
    let broker = source("systemd/bloom-broker@.service.in");
    let signer = source("systemd/bloom-signer@.service.in");
    for (name, unit) in [("Broker", &broker), ("Signer", &signer)] {
        for required in [
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "ProtectProc=invisible",
            "RestrictNamespaces=yes",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "LimitCORE=0",
        ] {
            assert!(
                unit.contains(required),
                "{name} sandbox is missing {required}"
            );
        }
    }
    assert!(broker.contains("User=bloom-broker-%i"));
    assert!(broker.contains("RestrictAddressFamilies=AF_UNIX AF_INET"));
    assert!(broker.contains("IPAddressAllow=localhost"));
    assert!(signer.contains("User=bloom-signer-%i"));
    assert!(signer.contains("PrivateNetwork=yes"));
    assert!(signer.contains("RestrictAddressFamilies=AF_UNIX"));
    assert!(!signer.contains("IPAddressAllow="));

    let aws_path = "systemd/instance-dropins/bloom-signer@LOGIN_UID.service.d/50-aws-kms.conf.in";
    let aws = source(aws_path);
    assert!(
        aws_path.contains("bloom-signer@LOGIN_UID.service.d/"),
        "AWS drop-in source must render onto an instance of bloom-signer@.service"
    );
    assert!(aws.contains("IPAddressDeny=any"));
    assert!(aws.contains("PrivateNetwork=no"));
    assert!(aws.contains("@AWS_KMS_IP_ALLOW_DIRECTIVES@"));
    assert!(aws.contains("LoadCredential=aws-credentials:"));
    assert!(
        !aws.contains("IPAddressAllow=any"),
        "AWS profile must not permit wildcard egress"
    );
}

#[test]
fn linux_time_policy_requires_multiple_authenticated_sources() {
    let chrony = source("chrony/bloom-nts.conf.in");
    assert!(chrony.contains("authselectmode require"));
    assert!(chrony.contains("minsources 2"));
    assert_eq!(
        chrony.lines().filter(|line| line.contains(" nts")).count(),
        2,
        "packaging must render at least two authenticated NTS sources"
    );
    assert!(
        !chrony.lines().any(|line| {
            let line = line.trim_start();
            (line.starts_with("server ") || line.starts_with("pool ")) && !line.contains(" nts")
        }),
        "unauthenticated selectable time source is forbidden"
    );
}

#[test]
fn audit_checkpoint_roots_are_principal_private_and_explicitly_wired() {
    let temporary_paths = source("tmpfiles.d/bloom-login.conf.in");
    for principal in ["broker", "signer"] {
        let checkpoint = format!("/var/lib/bloom/@LOGIN_UID@/{principal}/audit-checkpoints");
        assert!(temporary_paths.contains(&format!(
            "d {checkpoint} 0700 bloom-{principal}-@LOGIN_UID@ bloom-{principal}-@LOGIN_UID@"
        )));
        let service = source(&format!("systemd/bloom-{principal}@.service.in"));
        assert!(service.contains(&format!(
            "Environment=BLOOM_AUDIT_CHECKPOINT_DIR=/var/lib/bloom/%i/{principal}/audit-checkpoints"
        )));
        assert!(!service.contains("../"));
    }
}
