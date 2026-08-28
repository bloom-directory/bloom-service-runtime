//! Small, local tracing setup shared by installed Bloom processes.

#![forbid(unsafe_code)]
#![cfg(unix)]

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use tracing::{Span, field};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Destination and representation for service events.
#[derive(Clone, Debug)]
pub enum LogOutput {
    /// Human-readable output for an interactive process.
    Interactive,
    /// JSON Lines on stderr, suitable for journald.
    JsonStderr,
    /// JSON Lines appended securely to an installer-controlled file.
    JsonFile(SecureLogFile),
}

/// Installer-owned identity and mode expected for a canonical service log.
#[derive(Clone, Debug)]
pub struct SecureLogFile {
    pub path: PathBuf,
    pub expected_uid: u32,
    pub expected_gid: u32,
    pub expected_mode: u32,
}

impl SecureLogFile {
    pub fn new(path: impl Into<PathBuf>, expected_uid: u32, expected_gid: u32) -> Self {
        Self {
            path: path.into(),
            expected_uid,
            expected_gid,
            expected_mode: 0o640,
        }
    }

    pub fn with_mode(mut self, expected_mode: u32) -> Self {
        self.expected_mode = expected_mode;
        self
    }
}

/// Installs the process-global subscriber. Call this before loading service secrets.
pub fn init(role: &'static str, version: &'static str, output: LogOutput) -> Result<(), InitError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(filter);
    match output {
        LogOutput::Interactive => registry
            .with(fmt::layer().with_writer(io::stderr))
            .try_init()
            .map_err(|error| InitError::Subscriber(error.to_string())),
        LogOutput::JsonStderr => registry
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(true)
                    .with_writer(io::stderr),
            )
            .try_init()
            .map_err(|error| InitError::Subscriber(error.to_string())),
        LogOutput::JsonFile(file) => {
            SecureAppendWriter::validate(&file)?;
            registry
                .with(
                    fmt::layer()
                        .json()
                        .with_current_span(true)
                        .with_span_list(true)
                        .with_writer(SecureAppendWriter::new(file)),
                )
                .try_init()
                .map_err(|error| InitError::Subscriber(error.to_string()))
        }
    }?;

    tracing::info!(
        event = "service.startup",
        service_role = role,
        package_version = version,
        pid = std::process::id(),
        effective_uid = rustix_uid(),
    );
    Ok(())
}

/// Root span used after trusted enrollment metadata has been loaded.
pub fn service_span(
    role: &str,
    package_version: &str,
    service_id: &str,
    enrolled_login_uid: Option<u32>,
    release_digest: Option<&str>,
) -> Span {
    let span = tracing::info_span!(
        "service",
        service_role = role,
        package_version = package_version,
        pid = std::process::id(),
        effective_uid = rustix_uid(),
        service_id = service_id,
        enrolled_login_uid = field::Empty,
        release_digest = field::Empty,
    );
    if let Some(uid) = enrolled_login_uid {
        span.record("enrolled_login_uid", uid);
    }
    if let Some(digest) = release_digest {
        span.record("release_digest", digest);
    }
    span
}

#[derive(Debug)]
pub enum InitError {
    Io(io::Error),
    Subscriber(String),
}

impl std::fmt::Display for InitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "log destination is unavailable: {error}"),
            Self::Subscriber(error) => {
                write!(formatter, "tracing subscriber setup failed: {error}")
            }
        }
    }
}

impl std::error::Error for InitError {}

impl From<io::Error> for InitError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// A `MakeWriter` that buffers one formatter write and appends it under a
/// process-local lock. The path is reopened and checked for every event so
/// rotation does not leave the process writing to the renamed inode.
#[derive(Clone, Debug)]
pub struct SecureAppendWriter {
    file: Arc<SecureLogFile>,
    write_lock: Arc<Mutex<()>>,
}

impl SecureAppendWriter {
    pub fn new(file: SecureLogFile) -> Self {
        Self {
            file: Arc::new(file),
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn validate(expected: &SecureLogFile) -> io::Result<()> {
        let file = open_secure_append(&expected.path)?;
        validate_file(&file, expected)
    }
}

pub struct SecureEventWriter {
    destination: SecureAppendWriter,
    bytes: Vec<u8>,
}

impl Write for SecureEventWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        if self.bytes.ends_with(b"\n") {
            self.flush()?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.bytes.is_empty() {
            return Ok(());
        }
        let _guard = self
            .destination
            .write_lock
            .lock()
            .map_err(|_| io::Error::other("log append lock poisoned"))?;
        let mut file = open_secure_append(&self.destination.file.path)?;
        validate_file(&file, &self.destination.file)?;
        file.write_all(&self.bytes)?;
        self.bytes.clear();
        Ok(())
    }
}

impl Drop for SecureEventWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

impl<'a> fmt::MakeWriter<'a> for SecureAppendWriter {
    type Writer = SecureEventWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SecureEventWriter {
            destination: self.clone(),
            bytes: Vec::new(),
        }
    }
}

/// Parallel-safe subscriber writer for semantic event tests.
#[derive(Clone, Default)]
pub struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl CapturedWriter {
    pub fn bytes(&self) -> Vec<u8> {
        self.0.lock().expect("capture lock poisoned").clone()
    }

    pub fn text(&self) -> String {
        String::from_utf8(self.bytes()).expect("tracing formatter emitted UTF-8")
    }

    pub fn clear(&self) {
        self.0.lock().expect("capture lock poisoned").clear();
    }
}

pub struct CapturedEventWriter {
    destination: CapturedWriter,
    bytes: Vec<u8>,
}

impl Write for CapturedEventWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for CapturedEventWriter {
    fn drop(&mut self) {
        self.destination
            .0
            .lock()
            .expect("capture lock poisoned")
            .extend_from_slice(&self.bytes);
    }
}

impl<'a> fmt::MakeWriter<'a> for CapturedWriter {
    type Writer = CapturedEventWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CapturedEventWriter {
            destination: self.clone(),
            bytes: Vec::new(),
        }
    }
}

fn open_secure_append(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::other("log destination must be absolute"));
    }
    OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

fn validate_file(file: &File, expected: &SecureLogFile) -> io::Result<()> {
    let metadata = file.metadata()?;
    let file_type = metadata.file_type();
    if !file_type.is_file() || file_type.is_symlink() || file_type.is_socket() {
        return Err(io::Error::other("log destination is not a regular file"));
    }
    if metadata.uid() != expected.expected_uid || metadata.gid() != expected.expected_gid {
        return Err(io::Error::other(
            "log destination owner or group is unexpected",
        ));
    }
    if metadata.permissions().mode() & 0o7777 != expected.expected_mode {
        return Err(io::Error::other("log destination mode is unexpected"));
    }
    Ok(())
}

fn rustix_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_writer_keeps_parallel_events_contiguous() {
        let capture = CapturedWriter::default();
        std::thread::scope(|scope| {
            for index in 0..16 {
                let capture = capture.clone();
                scope.spawn(move || {
                    let mut writer = fmt::MakeWriter::make_writer(&capture);
                    writeln!(writer, "event-{index}").unwrap();
                });
            }
        });
        let lines = capture
            .text()
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 16);
        assert!(lines.iter().all(|line| line.starts_with("event-")));
    }

    #[test]
    fn secure_writer_reopens_after_rotation_and_rejects_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("service.jsonl");
        File::create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let expected = SecureLogFile::new(&path, metadata.uid(), metadata.gid());
        let destination = SecureAppendWriter::new(expected.clone());
        {
            let mut writer = fmt::MakeWriter::make_writer(&destination);
            writeln!(writer, "first").unwrap();
        }
        std::fs::rename(&path, directory.path().join("service.jsonl.0")).unwrap();
        File::create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        {
            let mut writer = fmt::MakeWriter::make_writer(&destination);
            writeln!(writer, "second").unwrap();
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second\n");

        let link = directory.path().join("link");
        std::os::unix::fs::symlink(directory.path().join("service.jsonl"), &link).unwrap();
        let link_expected = SecureLogFile::new(&link, metadata.uid(), metadata.gid());
        assert!(SecureAppendWriter::validate(&link_expected).is_err());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert!(SecureAppendWriter::validate(&expected).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let wrong_owner = SecureLogFile::new(&path, metadata.uid().wrapping_add(1), metadata.gid());
        assert!(SecureAppendWriter::validate(&wrong_owner).is_err());
    }

    #[test]
    fn json_formatter_includes_event_and_root_metadata() {
        let capture = CapturedWriter::default();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true)
                .with_writer(capture.clone()),
        );
        tracing::subscriber::with_default(subscriber, || {
            let span = service_span("broker", "1.2.3", "broker-1", Some(501), Some("abc123"));
            let _entered = span.enter();
            let request = tracing::info_span!("authenticated_request", operation_id = "op-1");
            let _request_entered = request.enter();
            tracing::info!(event = "service.ready");
        });
        let line: serde_json::Value = serde_json::from_str(capture.text().trim()).unwrap();
        assert_eq!(line["fields"]["event"], "service.ready");
        assert_eq!(line["span"]["operation_id"], "op-1");
        let spans = line["spans"].as_array().unwrap();
        let service = spans
            .iter()
            .find(|span| span["name"] == "service")
            .expect("outer service metadata span is retained");
        assert_eq!(service["service_id"], "broker-1");
        assert_eq!(service["package_version"], "1.2.3");
        assert_eq!(service["enrolled_login_uid"], 501);
    }
}
