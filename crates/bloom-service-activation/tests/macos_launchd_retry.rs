#[cfg(target_os = "macos")]
mod macos {
    use std::{
        fs,
        net::{Ipv4Addr, SocketAddrV4, TcpListener},
        process::Command,
        thread,
        time::{Duration, Instant},
    };

    const RUN_ENV: &str = "BLOOM_RUN_MACOS_LAUNCHD_W0";
    const CHILD_ENV: &str = "BLOOM_MACOS_LAUNCHD_W0_CHILD";
    const READY_ENV: &str = "BLOOM_MACOS_LAUNCHD_W0_READY";

    struct LoadedJob {
        domain: String,
        label: String,
    }

    impl Drop for LoadedJob {
        fn drop(&mut self) {
            let _ = Command::new("launchctl")
                .args(["bootout", &format!("{}/{}", self.domain, self.label)])
                .status();
        }
    }

    #[test]
    fn launchd_retries_canonical_listener_after_the_prior_owner_releases_it() {
        if std::env::var_os(CHILD_ENV).is_some() {
            let listener = bloom_service_activation::take_tcp_listener("broker-ceremony")
                .expect("launchd must hand the canonical listener to the waiting Broker");
            assert_eq!(
                listener.local_addr().unwrap(),
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18_734).into()
            );
            fs::write(std::env::var_os(READY_ENV).expect("ready path"), b"ready\n")
                .expect("publish activation readiness");
            thread::sleep(Duration::from_secs(2));
            return;
        }
        if std::env::var_os(RUN_ENV).is_none() {
            eprintln!(
                "macOS launchd mutation is confined to the disposable W0 CI lane; local workspace tests remain non-mutating"
            );
            return;
        }

        let foreign = TcpListener::bind((Ipv4Addr::LOCALHOST, 18_734))
            .expect("canonical port must begin free on the disposable runner");
        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let plist = directory.path().join("com.bloom.w0-retry.plist");
        let label = format!("com.bloom.w0-retry.{}", std::process::id());
        let executable = std::env::current_exe().unwrap();
        let uid = String::from_utf8(
            Command::new("id")
                .arg("-u")
                .output()
                .expect("read effective UID")
                .stdout,
        )
        .unwrap();
        let domain = format!("gui/{}", uid.trim());
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array><string>{executable}</string><string>--exact</string><string>macos::launchd_retries_canonical_listener_after_the_prior_owner_releases_it</string><string>--nocapture</string></array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>{child_env}</key><string>1</string>
    <key>{ready_env}</key><string>{ready}</string>
  </dict>
  <key>Sockets</key>
  <dict>
    <key>broker-ceremony</key>
    <dict>
      <key>SockNodeName</key><string>127.0.0.1</string>
      <key>SockServiceName</key><integer>18734</integer>
      <key>SockFamily</key><string>IPv4</string>
      <key>SockProtocol</key><string>TCP</string>
      <key>SockType</key><string>stream</string>
    </dict>
  </dict>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>1</integer>
</dict>
</plist>
"#,
            executable = xml_escape(&executable.to_string_lossy()),
            ready = xml_escape(&ready.to_string_lossy()),
            child_env = CHILD_ENV,
            ready_env = READY_ENV,
        );
        fs::write(&plist, xml).unwrap();

        let bootstrap = Command::new("launchctl")
            .args(["bootstrap", &domain])
            .arg(&plist)
            .output()
            .expect("bootstrap disposable LaunchAgent");
        let _job = LoadedJob {
            domain: domain.clone(),
            label: label.clone(),
        };
        thread::sleep(Duration::from_secs(2));
        assert!(
            !ready.exists(),
            "launchd handed out or shared the canonical listener while a foreign owner still held it"
        );
        drop(foreign);

        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline && !ready.exists() {
            thread::sleep(Duration::from_millis(200));
        }
        if !ready.exists() {
            let state = Command::new("launchctl")
                .args(["print", &format!("{domain}/{label}")])
                .output()
                .expect("inspect disposable LaunchAgent");
            panic!(
                "launchd did not retain/retry the waiting canonical listener after release\nbootstrap status: {}\nbootstrap stderr: {}\nlaunchd stdout: {}\nlaunchd stderr: {}",
                bootstrap.status,
                String::from_utf8_lossy(&bootstrap.stderr),
                String::from_utf8_lossy(&state.stdout),
                String::from_utf8_lossy(&state.stderr)
            );
        }
    }

    fn xml_escape(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn launchd_retry_is_exercised_only_on_the_disposable_macos_lane() {}
