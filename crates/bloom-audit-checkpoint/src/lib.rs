//! Fail-closed, packaging-selected storage for independently retained peer
//! audit heads.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write as _,
    os::unix::{
        fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        prelude::OsStrExt as _,
    },
    path::{Path, PathBuf},
};

use bloom_triad_protocol::{SignedJournalHead, Token};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const CHECKPOINT_SCHEMA: &str = "bloom.audit-checkpoint/1";

#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("audit checkpoint root is not a real directory")]
    InvalidRoot,
    #[error("audit checkpoint root owner {actual_uid} differs from expected UID {expected_uid}")]
    WrongOwner { expected_uid: u32, actual_uid: u32 },
    #[error("audit checkpoint root grants group or other access")]
    InsecurePermissions,
    #[error("audit checkpoint entry is malformed: {0}")]
    Malformed(String),
    #[error("audit checkpoint sequence would roll back")]
    SequenceRollback,
    #[error("audit checkpoint sequence conflicts with an existing signed head")]
    SequenceConflict,
    #[error("audit checkpoint head is not signed by the pinned peer key")]
    InvalidSignature,
    #[error("audit checkpoint head has no pinned peer audit key")]
    UnpinnedPeer,
    #[error("audit checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointRecord {
    schema: Token,
    recipient_service_id: Token,
    peer_head: SignedJournalHead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendOutcome {
    Appended,
    AlreadyPresent,
}

/// Injectable recipient-side sink used by Broker/Signer transport integration.
/// Implementations must preserve the monotonic, independently retained peer
/// head contract or return an error before a caller publishes mutation success.
pub trait CheckpointSink: Send + Sync {
    fn append_peer_head(
        &self,
        peer_head: &SignedJournalHead,
    ) -> Result<AppendOutcome, CheckpointError>;
}

pub struct CheckpointStore {
    root: PathBuf,
    recipient_service_id: Token,
    pinned_keys: BTreeMap<Token, (Token, VerifyingKey)>,
}

impl CheckpointStore {
    pub fn open(
        root: impl AsRef<Path>,
        expected_uid: u32,
        recipient_service_id: Token,
        pinned_keys: impl IntoIterator<Item = PinnedAuditKey>,
    ) -> Result<Self, CheckpointError> {
        let root = root.as_ref().to_path_buf();
        validate_root(&root, expected_uid)?;
        let mut keys = BTreeMap::new();
        for pinned in pinned_keys {
            if keys
                .insert(pinned.service_id, (pinned.key_id, pinned.verifying_key))
                .is_some()
            {
                return Err(CheckpointError::Malformed(
                    "duplicate pinned peer audit service".into(),
                ));
            }
        }
        let store = Self {
            root,
            recipient_service_id,
            pinned_keys: keys,
        };
        store.scan_records()?;
        Ok(store)
    }

    pub fn append(&self, peer_head: &SignedJournalHead) -> Result<AppendOutcome, CheckpointError> {
        self.verify_head(peer_head)?;
        let records = self.scan_records()?;
        let latest = records
            .iter()
            .filter(|record| record.peer_head.service_id == peer_head.service_id)
            .max_by_key(|record| record.peer_head.sequence.get());
        if let Some(latest) = latest {
            match peer_head
                .sequence
                .get()
                .cmp(&latest.peer_head.sequence.get())
            {
                std::cmp::Ordering::Less => return Err(CheckpointError::SequenceRollback),
                std::cmp::Ordering::Equal if &latest.peer_head == peer_head => {
                    return Ok(AppendOutcome::AlreadyPresent);
                }
                std::cmp::Ordering::Equal => return Err(CheckpointError::SequenceConflict),
                std::cmp::Ordering::Greater => {}
            }
        }

        let record = CheckpointRecord {
            schema: Token::new(CHECKPOINT_SCHEMA)
                .map_err(|error| CheckpointError::Malformed(error.to_string()))?,
            recipient_service_id: self.recipient_service_id.clone(),
            peer_head: peer_head.clone(),
        };
        let bytes = serde_jcs::to_vec(&record)
            .map_err(|error| CheckpointError::Malformed(error.to_string()))?;
        let path = self.root.join(checkpoint_filename(peer_head));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(&self.root)?.sync_all()?;
        Ok(AppendOutcome::Appended)
    }

    fn scan_records(&self) -> Result<Vec<CheckpointRecord>, CheckpointError> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.permissions().mode() & 0o7777 != 0o600
            {
                return Err(CheckpointError::Malformed(format!(
                    "unsafe entry {}",
                    String::from_utf8_lossy(entry.file_name().as_bytes())
                )));
            }
            let bytes = fs::read(entry.path())?;
            let record: CheckpointRecord = serde_json::from_slice(&bytes)
                .map_err(|error| CheckpointError::Malformed(error.to_string()))?;
            if serde_jcs::to_vec(&record)
                .map_err(|error| CheckpointError::Malformed(error.to_string()))?
                != bytes
            {
                return Err(CheckpointError::Malformed(
                    "checkpoint entry is not canonical JCS".into(),
                ));
            }
            if record.schema.as_str() != CHECKPOINT_SCHEMA
                || record.recipient_service_id != self.recipient_service_id
            {
                return Err(CheckpointError::Malformed(
                    "checkpoint schema or recipient mismatch".into(),
                ));
            }
            self.verify_head(&record.peer_head)?;
            if entry.file_name().as_bytes() != checkpoint_filename(&record.peer_head).as_bytes() {
                return Err(CheckpointError::Malformed(
                    "checkpoint filename does not bind its peer and sequence".into(),
                ));
            }
            records.push(record);
        }
        Ok(records)
    }

    fn verify_head(&self, head: &SignedJournalHead) -> Result<(), CheckpointError> {
        let (expected_key_id, verifying_key) = self
            .pinned_keys
            .get(&head.service_id)
            .ok_or(CheckpointError::UnpinnedPeer)?;
        if expected_key_id != &head.key_id {
            return Err(CheckpointError::InvalidSignature);
        }
        let signature_bytes: [u8; 64] = head
            .signature
            .decode()
            .try_into()
            .map_err(|_| CheckpointError::InvalidSignature)?;
        verifying_key
            .verify(
                &head.signature_message(),
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| CheckpointError::InvalidSignature)
    }
}

impl CheckpointSink for CheckpointStore {
    fn append_peer_head(
        &self,
        peer_head: &SignedJournalHead,
    ) -> Result<AppendOutcome, CheckpointError> {
        self.append(peer_head)
    }
}

pub struct PinnedAuditKey {
    pub service_id: Token,
    pub key_id: Token,
    pub verifying_key: VerifyingKey,
}

fn checkpoint_filename(head: &SignedJournalHead) -> String {
    let service_name = bloom_triad_protocol::Digest32::from_bytes(
        Sha256::digest(head.service_id.as_str().as_bytes()).into(),
    );
    format!("{}-{:020}.jcs", service_name, head.sequence.get())
}

fn validate_root(root: &Path, expected_uid: u32) -> Result<(), CheckpointError> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(CheckpointError::InvalidRoot);
    }
    if metadata.uid() != expected_uid {
        return Err(CheckpointError::WrongOwner {
            expected_uid,
            actual_uid: metadata.uid(),
        });
    }
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(CheckpointError::InsecurePermissions);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_triad_protocol::{Base64UrlBytes, DecimalU64, Digest32};
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::os::unix::fs::symlink;

    struct ForcedFailureSink;

    impl CheckpointSink for ForcedFailureSink {
        fn append_peer_head(
            &self,
            _peer_head: &SignedJournalHead,
        ) -> Result<AppendOutcome, CheckpointError> {
            Err(CheckpointError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "forced checkpoint failure",
            )))
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn head(sequence: u64, hash_byte: &str) -> SignedJournalHead {
        let mut head = SignedJournalHead {
            service_id: Token::new("bloom-signer").unwrap(),
            sequence: DecimalU64::new(sequence),
            head_hash: Digest32::new(hash_byte.repeat(32)).unwrap(),
            key_id: Token::new("signer-audit-1").unwrap(),
            signature: Base64UrlBytes::from_bytes(&[0; 64]),
        };
        head.signature =
            Base64UrlBytes::from_bytes(&signing_key().sign(&head.signature_message()).to_bytes());
        head
    }

    fn open_store_result(
        directory: &tempfile::TempDir,
    ) -> Result<CheckpointStore, CheckpointError> {
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        CheckpointStore::open(
            directory.path(),
            uid,
            Token::new("bloom-broker").unwrap(),
            [PinnedAuditKey {
                service_id: Token::new("bloom-signer").unwrap(),
                key_id: Token::new("signer-audit-1").unwrap(),
                verifying_key: signing_key().verifying_key(),
            }],
        )
    }

    fn open_store(directory: &tempfile::TempDir) -> CheckpointStore {
        open_store_result(directory).unwrap()
    }

    #[test]
    fn append_is_monotonic_idempotent_and_restart_safe() {
        let directory = tempfile::tempdir().unwrap();
        let store = open_store(&directory);
        assert_eq!(
            store.append(&head(7, "11")).unwrap(),
            AppendOutcome::Appended
        );
        assert_eq!(
            store.append(&head(7, "11")).unwrap(),
            AppendOutcome::AlreadyPresent
        );
        assert!(matches!(
            store.append(&head(7, "22")),
            Err(CheckpointError::SequenceConflict)
        ));
        assert_eq!(
            store.append(&head(8, "22")).unwrap(),
            AppendOutcome::Appended
        );
        assert!(matches!(
            store.append(&head(6, "33")),
            Err(CheckpointError::SequenceRollback)
        ));
        drop(store);
        let reopened = open_store(&directory);
        assert_eq!(
            reopened.append(&head(8, "22")).unwrap(),
            AppendOutcome::AlreadyPresent
        );
    }

    #[test]
    fn roots_and_entries_fail_closed_on_permissions_symlinks_and_tamper() {
        let insecure = tempfile::tempdir().unwrap();
        fs::set_permissions(insecure.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let uid = fs::metadata(insecure.path()).unwrap().uid();
        assert!(matches!(
            CheckpointStore::open(
                insecure.path(),
                uid,
                Token::new("bloom-broker").unwrap(),
                [PinnedAuditKey {
                    service_id: Token::new("bloom-signer").unwrap(),
                    key_id: Token::new("signer-audit-1").unwrap(),
                    verifying_key: signing_key().verifying_key(),
                }]
            ),
            Err(CheckpointError::InsecurePermissions)
        ));

        let directory = tempfile::tempdir().unwrap();
        let store = open_store(&directory);
        let mut forged = head(1, "11");
        forged.signature = Base64UrlBytes::from_bytes(&[9; 64]);
        assert!(matches!(
            store.append(&forged),
            Err(CheckpointError::InvalidSignature)
        ));
        store.append(&head(1, "11")).unwrap();
        let target = directory.path().join("target");
        fs::write(&target, b"{}").unwrap();
        let link = directory.path().join("linked.jcs");
        symlink(&target, &link).unwrap();
        assert!(matches!(
            store.append(&head(2, "22")),
            Err(CheckpointError::Malformed(_))
        ));
    }

    #[test]
    fn restart_rejects_filename_and_sequence_conflict_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let store = open_store(&directory);
        let first = head(4, "44");
        store.append(&first).unwrap();
        let mismatched = directory.path().join("wrong-00000000000000000004.jcs");
        let conflicting = CheckpointRecord {
            schema: Token::new(CHECKPOINT_SCHEMA).unwrap(),
            recipient_service_id: Token::new("bloom-broker").unwrap(),
            peer_head: head(4, "55"),
        };
        fs::write(&mismatched, serde_jcs::to_vec(&conflicting).unwrap()).unwrap();
        fs::set_permissions(&mismatched, fs::Permissions::from_mode(0o600)).unwrap();
        drop(store);
        assert!(matches!(
            open_store_result(&directory),
            Err(CheckpointError::Malformed(_))
        ));
    }

    #[test]
    fn restart_rejects_owner_only_but_noncanonical_entry_modes() {
        for mode in [0o400, 0o700] {
            let directory = tempfile::tempdir().unwrap();
            let store = open_store(&directory);
            let first = head(2, "22");
            store.append(&first).unwrap();
            fs::set_permissions(
                directory.path().join(checkpoint_filename(&first)),
                fs::Permissions::from_mode(mode),
            )
            .unwrap();
            drop(store);
            assert!(matches!(
                open_store_result(&directory),
                Err(CheckpointError::Malformed(_))
            ));
        }
    }

    #[test]
    fn injectable_sink_propagates_forced_write_failure() {
        let sink: &dyn CheckpointSink = &ForcedFailureSink;
        assert!(matches!(
            sink.append_peer_head(&head(1, "11")),
            Err(CheckpointError::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied
        ));
    }
}
