//! Verification of the root-owned macOS packet-filter health attestation.

use std::{
    fs,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use bloom_triad_protocol::{Digest32, ProtocolError, ProtocolErrorCode};
use serde::Deserialize;

const STATUS_SCHEMA: &str = "bloom.macos-platform-status.2";
const TRUSTED_TIME_SOURCE: &str = "macos-managed-timed";
const MAX_FUTURE_SKEW_MS: u64 = 1_000;

#[derive(Clone)]
pub struct NetworkContainmentGuard {
    path: PathBuf,
    login_uid: u32,
    build_digest: Digest32,
    maximum_age_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkContainmentStatus {
    schema: String,
    login_uid: u32,
    build_digest: Digest32,
    anchor_sha256: Digest32,
    trusted_time_source: String,
    automatic_time_enabled: bool,
    timed_service_loaded: bool,
    trusted_time_available: bool,
    checked_at_unix_ms: u64,
    available: bool,
}

impl NetworkContainmentGuard {
    pub fn new(
        path: impl Into<PathBuf>,
        login_uid: u32,
        build_digest: Digest32,
        maximum_age_ms: u64,
    ) -> Result<Self, ProtocolError> {
        if login_uid == 0 || maximum_age_ms == 0 {
            return Err(unavailable("invalid network-containment guard"));
        }
        Ok(Self {
            path: path.into(),
            login_uid,
            build_digest,
            maximum_age_ms,
        })
    }

    pub fn check(&self) -> Result<(), ProtocolError> {
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| unavailable(format!("inspect containment status: {error}")))?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != 0o644
            || metadata.nlink() != 1
        {
            return Err(unavailable(
                "network-containment status has unsafe metadata",
            ));
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| unavailable("system time precedes the Unix epoch"))?
            .as_millis()
            .try_into()
            .map_err(|_| unavailable("system time does not fit u64 milliseconds"))?;
        let bytes = fs::read(&self.path)
            .map_err(|error| unavailable(format!("read containment status: {error}")))?;
        validate_status(
            &bytes,
            self.login_uid,
            &self.build_digest,
            now_ms,
            self.maximum_age_ms,
        )
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn validate_status(
    bytes: &[u8],
    login_uid: u32,
    build_digest: &Digest32,
    now_ms: u64,
    maximum_age_ms: u64,
) -> Result<(), ProtocolError> {
    let status: NetworkContainmentStatus = serde_json::from_slice(bytes)
        .map_err(|error| unavailable(format!("decode containment status: {error}")))?;
    let _anchor_digest = status.anchor_sha256;
    if status.schema != STATUS_SCHEMA
        || status.login_uid != login_uid
        || &status.build_digest != build_digest
        || status.trusted_time_source != TRUSTED_TIME_SOURCE
        || !status.automatic_time_enabled
        || !status.timed_service_loaded
        || !status.trusted_time_available
        || !status.available
        || status.checked_at_unix_ms > now_ms.saturating_add(MAX_FUTURE_SKEW_MS)
        || now_ms.saturating_sub(status.checked_at_unix_ms) > maximum_age_ms
    {
        return Err(unavailable(
            "root packet-filter containment is unavailable or stale",
        ));
    }
    Ok(())
}

fn unavailable(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(
        available: bool,
        trusted_time_source: &str,
        trusted_time_available: bool,
        checked_at_unix_ms: u64,
    ) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": STATUS_SCHEMA,
            "login_uid": 501,
            "build_digest": "11".repeat(32),
            "anchor_sha256": "22".repeat(32),
            "trusted_time_source": trusted_time_source,
            "automatic_time_enabled": trusted_time_available,
            "timed_service_loaded": trusted_time_available,
            "trusted_time_available": trusted_time_available,
            "checked_at_unix_ms": checked_at_unix_ms,
            "available": available,
        }))
        .unwrap()
    }

    #[test]
    fn containment_status_is_exact_build_uid_available_and_fresh() {
        let digest = Digest32::new("11".repeat(32)).unwrap();
        validate_status(
            &status(true, TRUSTED_TIME_SOURCE, true, 10_000),
            501,
            &digest,
            12_000,
            3_000,
        )
        .unwrap();
        for rejected in [
            status(false, TRUSTED_TIME_SOURCE, true, 10_000),
            status(true, TRUSTED_TIME_SOURCE, false, 10_000),
            status(true, "peer-supplied-time", true, 10_000),
            status(true, TRUSTED_TIME_SOURCE, true, 8_999),
            status(true, TRUSTED_TIME_SOURCE, true, 13_001),
        ] {
            assert_eq!(
                validate_status(&rejected, 501, &digest, 12_000, 3_000)
                    .unwrap_err()
                    .code,
                ProtocolErrorCode::ServiceUnavailable
            );
        }
        assert!(
            validate_status(
                &status(true, TRUSTED_TIME_SOURCE, true, 10_000),
                502,
                &digest,
                12_000,
                3_000
            )
            .is_err()
        );
        assert!(
            validate_status(
                &status(true, TRUSTED_TIME_SOURCE, true, 10_000),
                501,
                &Digest32::new("33".repeat(32)).unwrap(),
                12_000,
                3_000,
            )
            .is_err()
        );
    }
}
