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
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use bloom_triad_protocol::{SignedJournalHead, Token};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const CHECKPOINT_SCHEMA: &str = "bloom.audit-checkpoint/1";
static CHECKPOINT_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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

    fn latest_peer_head(
        &self,
        _service_id: &Token,
    ) -> Result<Option<SignedJournalHead>, CheckpointError> {
        Ok(None)
    }
}

pub struct CheckpointStore {
    root: PathBuf,
    expected_uid: u32,
    recipient_service_id: Token,
    peer_keys: BTreeMap<Token, PeerKeySet>,
    handovers: BTreeMap<(Token, Token), ApplicationKeyHandover>,
    operation: Mutex<()>,
    state: Mutex<CheckpointState>,
    #[cfg(test)]
    scan_count: AtomicU64,
    #[cfg(test)]
    publish_barrier: Mutex<Option<std::sync::Arc<std::sync::Barrier>>>,
}

struct PeerKeySet {
    current_key_id: Token,
    keys: BTreeMap<Token, VerifyingKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootStamp {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    modified_secs: i64,
    modified_nanos: i64,
    changed_secs: i64,
    changed_nanos: i64,
}

struct CheckpointState {
    root_stamp: RootStamp,
    latest: BTreeMap<Token, SignedJournalHead>,
    record_stamps: BTreeMap<PathBuf, RecordStamp>,
}

struct ScannedRecords {
    records: Vec<CheckpointRecord>,
    root_stamp: RootStamp,
    record_stamps: BTreeMap<PathBuf, RecordStamp>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecordStamp {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    links: u64,
    size: u64,
    modified_secs: i64,
    modified_nanos: i64,
    changed_secs: i64,
    changed_nanos: i64,
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
        Self::open_with_history(
            root,
            expected_uid,
            recipient_service_id,
            pinned_keys,
            std::iter::empty(),
            std::iter::empty(),
        )
    }

    /// Opens a checkpoint root with exactly one live application key per peer,
    /// plus packaging-owned verification-only history and handover tuples.
    /// Historical keys can validate retained records but can never append a
    /// newly observed live head.
    pub fn open_with_history(
        root: impl AsRef<Path>,
        expected_uid: u32,
        recipient_service_id: Token,
        current_keys: impl IntoIterator<Item = PinnedAuditKey>,
        historical_keys: impl IntoIterator<Item = PinnedAuditKey>,
        handovers: impl IntoIterator<Item = ApplicationKeyHandover>,
    ) -> Result<Self, CheckpointError> {
        let root = root.as_ref().to_path_buf();
        validate_root(&root, expected_uid)?;
        let mut peer_keys = BTreeMap::new();
        for pinned in current_keys {
            let mut keys = BTreeMap::new();
            keys.insert(pinned.key_id.clone(), pinned.verifying_key);
            if peer_keys
                .insert(
                    pinned.service_id,
                    PeerKeySet {
                        current_key_id: pinned.key_id,
                        keys,
                    },
                )
                .is_some()
            {
                return Err(CheckpointError::Malformed(
                    "duplicate current peer application service".into(),
                ));
            }
        }
        for pinned in historical_keys {
            let key_set = peer_keys.get_mut(&pinned.service_id).ok_or_else(|| {
                CheckpointError::Malformed(
                    "historical application key has no current peer service".into(),
                )
            })?;
            if pinned.key_id == key_set.current_key_id
                || key_set
                    .keys
                    .insert(pinned.key_id, pinned.verifying_key)
                    .is_some()
            {
                return Err(CheckpointError::Malformed(
                    "duplicate current or historical peer application key".into(),
                ));
            }
        }
        let mut handover_map = BTreeMap::new();
        for handover in handovers {
            let key_set = peer_keys.get(&handover.service_id).ok_or_else(|| {
                CheckpointError::Malformed("handover has no pinned peer service".into())
            })?;
            if handover.old_key_id == handover.new_key_id
                || !key_set.keys.contains_key(&handover.old_key_id)
                || !key_set.keys.contains_key(&handover.new_key_id)
            {
                return Err(CheckpointError::Malformed(
                    "handover keys are equal or are not present in packaging key history".into(),
                ));
            }
            if handover_map
                .insert(
                    (handover.service_id.clone(), handover.new_key_id.clone()),
                    handover,
                )
                .is_some()
            {
                return Err(CheckpointError::Malformed(
                    "duplicate application-key handover".into(),
                ));
            }
        }
        let initial_root_stamp = root_stamp(&root, expected_uid)?;
        let store = Self {
            root,
            expected_uid,
            recipient_service_id,
            peer_keys,
            handovers: handover_map,
            operation: Mutex::new(()),
            state: Mutex::new(CheckpointState {
                root_stamp: initial_root_stamp,
                latest: BTreeMap::new(),
                record_stamps: BTreeMap::new(),
            }),
            #[cfg(test)]
            scan_count: AtomicU64::new(0),
            #[cfg(test)]
            publish_barrier: Mutex::new(None),
        };
        let scanned = store.scan_records()?;
        store.replace_cached_state(&scanned.records, scanned.root_stamp, scanned.record_stamps)?;
        Ok(store)
    }

    pub fn append(&self, peer_head: &SignedJournalHead) -> Result<AppendOutcome, CheckpointError> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| CheckpointError::Malformed("checkpoint operation lock poisoned".into()))?;
        self.verify_live_head(peer_head)?;
        if self.cached_head_is_exact(peer_head)? {
            return Ok(AppendOutcome::AlreadyPresent);
        }

        // Advancing, conflicting, or rolled-back heads retain the original
        // fail-closed behavior: reconcile the complete on-disk chain before
        // making a decision. Only an exact, already-verified tail is eligible
        // for the constant-time fast path above.
        let scanned = self.scan_records()?;
        self.replace_cached_state(&scanned.records, scanned.root_stamp, scanned.record_stamps)?;
        let records = scanned.records;
        let latest = records
            .iter()
            .rev()
            .find(|record| record.peer_head.service_id == peer_head.service_id);
        if let Some(latest) = latest {
            if latest.peer_head.key_id != peer_head.key_id
                && !self.valid_handover(&latest.peer_head, peer_head)
            {
                return Err(CheckpointError::SequenceConflict);
            }
            match peer_head
                .sequence
                .get()
                .cmp(&latest.peer_head.sequence.get())
            {
                std::cmp::Ordering::Less => return Err(CheckpointError::SequenceRollback),
                std::cmp::Ordering::Equal if &latest.peer_head == peer_head => {
                    return Ok(AppendOutcome::AlreadyPresent);
                }
                std::cmp::Ordering::Equal
                    if self.valid_equal_sequence_handover(&latest.peer_head, peer_head) => {}
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
        let parent = self.root.parent().ok_or(CheckpointError::InvalidRoot)?;
        let temporary = parent.join(format!(
            ".bloom-checkpoint-{}-{}-{}.new",
            std::process::id(),
            CHECKPOINT_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed),
            checkpoint_filename(peer_head)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        drop(file);
        #[cfg(test)]
        let publish_barrier = self.publish_barrier.lock().unwrap().clone();
        #[cfg(test)]
        if let Some(barrier) = publish_barrier {
            barrier.wait();
        }
        let linked = fs::hard_link(&temporary, &path);
        let _ = fs::remove_file(&temporary);
        match linked {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let outcome = self.validate_exact_existing(&path, &bytes, peer_head)?;
                // Reconcile after a competing publisher so a concurrent
                // higher sequence or malformed sibling cannot be hidden by
                // the idempotent target record.
                let scanned = self.scan_records()?;
                self.replace_cached_state(
                    &scanned.records,
                    scanned.root_stamp,
                    scanned.record_stamps,
                )?;
                return Ok(outcome);
            }
            Err(error) => return Err(error.into()),
        }
        File::open(&self.root)?.sync_all()?;
        // A second store can publish a higher head between our preflight scan
        // and link. Reconcile after every new publication before caching so an
        // inter-process conflict or rollback is never masked by local state.
        let scanned = self.scan_records()?;
        self.replace_cached_state(&scanned.records, scanned.root_stamp, scanned.record_stamps)?;
        Ok(AppendOutcome::Appended)
    }

    pub fn latest(&self, service_id: &Token) -> Result<Option<SignedJournalHead>, CheckpointError> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| CheckpointError::Malformed("checkpoint operation lock poisoned".into()))?;
        let stamp = root_stamp(&self.root, self.expected_uid)?;
        let cached = {
            let state = self.lock_state()?;
            (state.root_stamp == stamp).then(|| {
                (
                    state.latest.get(service_id).cloned(),
                    state.record_stamps.clone(),
                )
            })
        };
        if let Some((cached, record_stamps)) = cached {
            if self.record_stamps_unchanged(&record_stamps)? {
                if let Some(head) = cached.as_ref() {
                    self.validate_cached_record(head)?;
                }
                return Ok(cached);
            }
        }

        let scanned = self.scan_records()?;
        self.replace_cached_state(&scanned.records, scanned.root_stamp, scanned.record_stamps)?;
        Ok(scanned
            .records
            .into_iter()
            .rev()
            .find(|record| &record.peer_head.service_id == service_id)
            .map(|record| record.peer_head))
    }

    fn scan_records(&self) -> Result<ScannedRecords, CheckpointError> {
        #[cfg(test)]
        self.scan_count.fetch_add(1, Ordering::Relaxed);
        for _ in 0..3 {
            let before = root_stamp(&self.root, self.expected_uid)?;
            let mut records = Vec::new();
            let mut record_stamps = BTreeMap::new();
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
                record_stamps.insert(entry.path(), record_stamp_from_metadata(&metadata));
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
                self.verify_retained_head(&record.peer_head)?;
                if entry.file_name().as_bytes() != checkpoint_filename(&record.peer_head).as_bytes()
                {
                    return Err(CheckpointError::Malformed(
                        "checkpoint filename does not bind its peer and sequence".into(),
                    ));
                }
                records.push(record);
            }
            self.verify_record_chains(&mut records)?;
            let after = root_stamp(&self.root, self.expected_uid)?;
            if before == after {
                return Ok(ScannedRecords {
                    records,
                    root_stamp: after,
                    record_stamps,
                });
            }
        }
        Err(CheckpointError::Malformed(
            "checkpoint root changed repeatedly during reconciliation".into(),
        ))
    }

    fn cached_head_is_exact(&self, peer_head: &SignedJournalHead) -> Result<bool, CheckpointError> {
        let stamp = root_stamp(&self.root, self.expected_uid)?;
        let cached = {
            let state = self.lock_state()?;
            if state.root_stamp != stamp {
                None
            } else {
                Some((
                    state.latest.get(&peer_head.service_id).cloned(),
                    state.record_stamps.clone(),
                ))
            }
        };
        let Some((cached, record_stamps)) = cached else {
            return Ok(false);
        };
        if !self.record_stamps_unchanged(&record_stamps)? {
            return Ok(false);
        }
        let Some(cached) = cached else {
            return Ok(false);
        };
        if cached != *peer_head {
            return Ok(false);
        }
        // Reading and validating the single cached tail keeps in-place
        // replacement/tamper fail-closed without rescanning an ever-growing
        // history for an unchanged authenticated head.
        self.validate_cached_record(&cached)?;
        Ok(true)
    }

    fn record_stamps_unchanged(
        &self,
        expected: &BTreeMap<PathBuf, RecordStamp>,
    ) -> Result<bool, CheckpointError> {
        for (path, expected_stamp) in expected {
            if record_stamp(path)? != *expected_stamp {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn validate_cached_record(&self, head: &SignedJournalHead) -> Result<(), CheckpointError> {
        let record = CheckpointRecord {
            schema: Token::new(CHECKPOINT_SCHEMA)
                .map_err(|error| CheckpointError::Malformed(error.to_string()))?,
            recipient_service_id: self.recipient_service_id.clone(),
            peer_head: head.clone(),
        };
        let expected_bytes = serde_jcs::to_vec(&record)
            .map_err(|error| CheckpointError::Malformed(error.to_string()))?;
        self.validate_exact_record(
            &self.root.join(checkpoint_filename(head)),
            &expected_bytes,
            head,
        )
    }

    fn replace_cached_state(
        &self,
        records: &[CheckpointRecord],
        stamp: RootStamp,
        record_stamps: BTreeMap<PathBuf, RecordStamp>,
    ) -> Result<(), CheckpointError> {
        let latest = records
            .iter()
            .map(|record| {
                (
                    record.peer_head.service_id.clone(),
                    record.peer_head.clone(),
                )
            })
            .collect();
        *self.lock_state()? = CheckpointState {
            root_stamp: stamp,
            latest,
            record_stamps,
        };
        Ok(())
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, CheckpointState>, CheckpointError> {
        self.state
            .lock()
            .map_err(|_| CheckpointError::Malformed("checkpoint cache lock poisoned".into()))
    }

    fn verify_live_head(&self, head: &SignedJournalHead) -> Result<(), CheckpointError> {
        let keys = self
            .peer_keys
            .get(&head.service_id)
            .ok_or(CheckpointError::UnpinnedPeer)?;
        if keys.current_key_id != head.key_id {
            return Err(CheckpointError::InvalidSignature);
        }
        self.verify_retained_head(head)
    }

    fn validate_exact_existing(
        &self,
        path: &Path,
        expected_bytes: &[u8],
        expected_head: &SignedJournalHead,
    ) -> Result<AppendOutcome, CheckpointError> {
        self.validate_exact_record(path, expected_bytes, expected_head)?;
        // The competing publisher may not yet have completed its own directory
        // fsync.  Make the observed link durable before reporting idempotent
        // success to this caller as well.
        File::open(&self.root)?.sync_all()?;
        Ok(AppendOutcome::AlreadyPresent)
    }

    fn validate_exact_record(
        &self,
        path: &Path,
        expected_bytes: &[u8],
        expected_head: &SignedJournalHead,
    ) -> Result<(), CheckpointError> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err(CheckpointError::Malformed(
                "existing checkpoint path is unsafe".into(),
            ));
        }
        let bytes = fs::read(path)?;
        if bytes != expected_bytes {
            return Err(CheckpointError::SequenceConflict);
        }
        let record: CheckpointRecord = serde_json::from_slice(&bytes)
            .map_err(|error| CheckpointError::Malformed(error.to_string()))?;
        let expected_filename = checkpoint_filename(expected_head);
        if serde_jcs::to_vec(&record)
            .map_err(|error| CheckpointError::Malformed(error.to_string()))?
            != bytes
            || record.schema.as_str() != CHECKPOINT_SCHEMA
            || record.recipient_service_id != self.recipient_service_id
            || &record.peer_head != expected_head
            || path.file_name().and_then(|name| name.to_str()) != Some(expected_filename.as_str())
        {
            return Err(CheckpointError::SequenceConflict);
        }
        self.verify_retained_head(&record.peer_head)?;
        Ok(())
    }

    fn verify_retained_head(&self, head: &SignedJournalHead) -> Result<(), CheckpointError> {
        let verifying_key = self
            .peer_keys
            .get(&head.service_id)
            .and_then(|keys| keys.keys.get(&head.key_id))
            .ok_or(CheckpointError::UnpinnedPeer)?;
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

    fn valid_equal_sequence_handover(
        &self,
        old: &SignedJournalHead,
        new: &SignedJournalHead,
    ) -> bool {
        old.sequence == new.sequence
            && old.head_hash == new.head_hash
            && self.valid_handover(old, new)
    }

    fn valid_handover(&self, old: &SignedJournalHead, new: &SignedJournalHead) -> bool {
        old.service_id == new.service_id
            && old.sequence == new.sequence
            && self
                .handovers
                .get(&(new.service_id.clone(), new.key_id.clone()))
                .is_some_and(|handover| {
                    handover.old_key_id == old.key_id
                        && handover.sequence == old.sequence
                        && handover.head_hash == old.head_hash
                })
    }

    fn verify_record_chains(
        &self,
        records: &mut [CheckpointRecord],
    ) -> Result<(), CheckpointError> {
        records.sort_by(|left, right| {
            left.peer_head
                .service_id
                .cmp(&right.peer_head.service_id)
                .then_with(|| {
                    left.peer_head
                        .sequence
                        .get()
                        .cmp(&right.peer_head.sequence.get())
                })
                .then_with(|| {
                    // At an authorized equal-sequence handover the old record
                    // is logically before the new one, independent of names.
                    if self.valid_equal_sequence_handover(&left.peer_head, &right.peer_head) {
                        std::cmp::Ordering::Less
                    } else if self.valid_equal_sequence_handover(&right.peer_head, &left.peer_head)
                    {
                        std::cmp::Ordering::Greater
                    } else {
                        left.peer_head.key_id.cmp(&right.peer_head.key_id)
                    }
                })
        });
        let mut latest: BTreeMap<Token, SignedJournalHead> = BTreeMap::new();
        let mut consumed: BTreeMap<(Token, Token), ()> = BTreeMap::new();
        for record in records.iter() {
            let head = &record.peer_head;
            if let Some(previous) = latest.get(&head.service_id) {
                if head.sequence.get() < previous.sequence.get() {
                    return Err(CheckpointError::SequenceRollback);
                }
                if head.key_id == previous.key_id {
                    if head.sequence == previous.sequence && head != previous {
                        return Err(CheckpointError::SequenceConflict);
                    }
                } else {
                    let handover_key = (head.service_id.clone(), head.key_id.clone());
                    let handover = self
                        .handovers
                        .get(&handover_key)
                        .ok_or(CheckpointError::SequenceConflict)?;
                    if consumed.insert(handover_key, ()).is_some()
                        || handover.old_key_id != previous.key_id
                        || handover.sequence != previous.sequence
                        || handover.head_hash != previous.head_hash
                        || (head.sequence == previous.sequence
                            && head.head_hash != previous.head_hash)
                    {
                        return Err(CheckpointError::SequenceConflict);
                    }
                }
            }
            latest.insert(head.service_id.clone(), head.clone());
        }
        Ok(())
    }
}

impl CheckpointSink for CheckpointStore {
    fn append_peer_head(
        &self,
        peer_head: &SignedJournalHead,
    ) -> Result<AppendOutcome, CheckpointError> {
        self.append(peer_head)
    }

    fn latest_peer_head(
        &self,
        service_id: &Token,
    ) -> Result<Option<SignedJournalHead>, CheckpointError> {
        self.latest(service_id)
    }
}

pub struct PinnedAuditKey {
    pub service_id: Token,
    pub key_id: Token,
    pub verifying_key: VerifyingKey,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEdgeHistory {
    schema: String,
    historical_keys: Vec<AuthorityEdgeHistoricalKey>,
    handovers: Vec<ApplicationKeyHandover>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityEdgeHistoricalKey {
    service_id: String,
    key_id: String,
    public_key_hex: String,
}

impl AuthorityEdgeHistory {
    pub fn empty() -> Self {
        Self {
            schema: "bloom.authority-edge-application-history.1".into(),
            historical_keys: Vec::new(),
            handovers: Vec::new(),
        }
    }

    pub fn load_trusted(
        path: impl AsRef<Path>,
        expected_uid: u32,
    ) -> Result<Self, CheckpointError> {
        let metadata = fs::symlink_metadata(path.as_ref())?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != expected_uid
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(CheckpointError::Malformed(
                "authority-edge history has unsafe ownership, type, links, or mode".into(),
            ));
        }
        let document: Self = serde_json::from_slice(&fs::read(path.as_ref())?)
            .map_err(|error| CheckpointError::Malformed(error.to_string()))?;
        if document.schema != "bloom.authority-edge-application-history.1" {
            return Err(CheckpointError::Malformed(
                "unsupported authority-edge application history schema".into(),
            ));
        }
        Ok(document)
    }

    pub fn historical_pins_for(
        &self,
        services: &[&Token],
    ) -> Result<Vec<PinnedAuditKey>, CheckpointError> {
        self.historical_keys
            .iter()
            .filter(|entry| {
                services
                    .iter()
                    .any(|service| service.as_str() == entry.service_id)
            })
            .map(|entry| {
                let bytes: [u8; 32] = hex::decode(&entry.public_key_hex)
                    .map_err(|_| CheckpointError::Malformed("history key is not hex".into()))?
                    .try_into()
                    .map_err(|_| {
                        CheckpointError::Malformed("history key must be 32 bytes".into())
                    })?;
                Ok(PinnedAuditKey {
                    service_id: Token::new(entry.service_id.clone())
                        .map_err(|error| CheckpointError::Malformed(error.to_string()))?,
                    key_id: Token::new(entry.key_id.clone())
                        .map_err(|error| CheckpointError::Malformed(error.to_string()))?,
                    verifying_key: VerifyingKey::from_bytes(&bytes)
                        .map_err(|_| CheckpointError::Malformed("invalid history key".into()))?,
                })
            })
            .collect()
    }

    pub fn handovers_for(&self, services: &[&Token]) -> Vec<ApplicationKeyHandover> {
        self.handovers
            .iter()
            .filter(|handover| services.contains(&&handover.service_id))
            .cloned()
            .collect()
    }
}

/// Exact packaging-owned transition from a retired application key to its
/// successor. It is verification metadata, not a live transport credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationKeyHandover {
    pub service_id: Token,
    pub old_key_id: Token,
    pub new_key_id: Token,
    pub sequence: bloom_triad_protocol::DecimalU64,
    pub head_hash: bloom_triad_protocol::Digest32,
}

fn checkpoint_filename(head: &SignedJournalHead) -> String {
    let service_name = bloom_triad_protocol::Digest32::from_bytes(
        Sha256::digest(head.service_id.as_str().as_bytes()).into(),
    );
    let key_name = bloom_triad_protocol::Digest32::from_bytes(
        Sha256::digest(head.key_id.as_str().as_bytes()).into(),
    );
    format!(
        "{}-{:020}-{}.jcs",
        service_name,
        head.sequence.get(),
        key_name
    )
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

fn root_stamp(root: &Path, expected_uid: u32) -> Result<RootStamp, CheckpointError> {
    validate_root(root, expected_uid)?;
    let metadata = fs::symlink_metadata(root)?;
    Ok(RootStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        modified_secs: metadata.mtime(),
        modified_nanos: metadata.mtime_nsec(),
        changed_secs: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
    })
}

fn record_stamp(path: &Path) -> Result<RecordStamp, CheckpointError> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(record_stamp_from_metadata(&metadata))
}

fn record_stamp_from_metadata(metadata: &fs::Metadata) -> RecordStamp {
    RecordStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        links: metadata.nlink(),
        size: metadata.size(),
        modified_secs: metadata.mtime(),
        modified_nanos: metadata.mtime_nsec(),
        changed_secs: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
    }
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

    fn rotated_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[8; 32])
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

    fn keyed_head(
        signing_key: &SigningKey,
        key_id: &str,
        sequence: u64,
        hash_byte: &str,
    ) -> SignedJournalHead {
        let mut head = SignedJournalHead {
            service_id: Token::new("bloom-signer").unwrap(),
            sequence: DecimalU64::new(sequence),
            head_hash: Digest32::new(hash_byte.repeat(32)).unwrap(),
            key_id: Token::new(key_id).unwrap(),
            signature: Base64UrlBytes::from_bytes(&[0; 64]),
        };
        head.signature =
            Base64UrlBytes::from_bytes(&signing_key.sign(&head.signature_message()).to_bytes());
        head
    }

    fn open_rotated_store(
        directory: &tempfile::TempDir,
        include_history: bool,
        handover: Option<ApplicationKeyHandover>,
    ) -> Result<CheckpointStore, CheckpointError> {
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        CheckpointStore::open_with_history(
            directory.path(),
            uid,
            Token::new("bloom-broker").unwrap(),
            [PinnedAuditKey {
                service_id: Token::new("bloom-signer").unwrap(),
                key_id: Token::new("signer-app-2").unwrap(),
                verifying_key: rotated_signing_key().verifying_key(),
            }],
            include_history.then_some(PinnedAuditKey {
                service_id: Token::new("bloom-signer").unwrap(),
                key_id: Token::new("signer-audit-1").unwrap(),
                verifying_key: signing_key().verifying_key(),
            }),
            handover,
        )
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
        // DecimalU64's canonical representation is textual; retained records
        // must be ordered numerically across the 9 -> 10 boundary.
        assert_eq!(
            store.append(&head(9, "33")).unwrap(),
            AppendOutcome::Appended
        );
        assert_eq!(
            store.append(&head(10, "44")).unwrap(),
            AppendOutcome::Appended
        );
        assert_eq!(
            store.append(&head(11, "55")).unwrap(),
            AppendOutcome::Appended
        );
        drop(store);
        let reopened = open_store(&directory);
        assert_eq!(
            reopened.append(&head(11, "55")).unwrap(),
            AppendOutcome::AlreadyPresent
        );
    }

    #[test]
    fn unchanged_authenticated_head_has_bounded_disk_work() {
        let directory = tempfile::tempdir().unwrap();
        let store = open_store(&directory);
        let mut expected = head(7, "11");
        assert_eq!(store.scan_count.load(Ordering::Relaxed), 1);
        assert_eq!(store.append(&expected).unwrap(), AppendOutcome::Appended);
        for sequence in 8..=39 {
            expected = head(sequence, "11");
            assert_eq!(store.append(&expected).unwrap(), AppendOutcome::Appended);
        }
        let scans_after_publication = store.scan_count.load(Ordering::Relaxed);
        assert_eq!(scans_after_publication, 67);

        let started = std::time::Instant::now();
        for _ in 0..1_000 {
            assert_eq!(
                store.append(&expected).unwrap(),
                AppendOutcome::AlreadyPresent
            );
        }

        assert_eq!(
            store.scan_count.load(Ordering::Relaxed),
            scans_after_publication,
            "an unchanged peer head must not rescan retained history"
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 33);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "unchanged peer-head idempotence exceeded its bounded runtime"
        );
    }

    #[test]
    fn unchanged_head_fast_path_rejects_disk_tamper_and_directory_conflicts() {
        let directory = tempfile::tempdir().unwrap();
        let store = open_store(&directory);
        let expected = head(7, "11");
        store.append(&expected).unwrap();

        let path = directory.path().join(checkpoint_filename(&expected));
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(
            store.append(&expected).is_err(),
            "tail in-place tamper must fail before unchanged-head admission"
        );

        let record = CheckpointRecord {
            schema: Token::new(CHECKPOINT_SCHEMA).unwrap(),
            recipient_service_id: Token::new("bloom-broker").unwrap(),
            peer_head: expected.clone(),
        };
        fs::write(&path, serde_jcs::to_vec(&record).unwrap()).unwrap();
        let latest = head(8, "22");
        store.append(&latest).unwrap();
        let mut historical_bytes = fs::read(&path).unwrap();
        *historical_bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, historical_bytes).unwrap();
        assert!(
            store.append(&latest).is_err(),
            "historical in-place tamper must fail before unchanged-head admission"
        );

        // Restore the exact record, then prove an added unsafe sibling changes
        // the root stamp and forces full fail-closed reconciliation.
        fs::write(&path, serde_jcs::to_vec(&record).unwrap()).unwrap();
        let target = directory.path().join("outside");
        fs::write(&target, b"{}").unwrap();
        let link = directory.path().join("unsafe.jcs");
        symlink(&target, &link).unwrap();
        assert!(matches!(
            store.append(&expected),
            Err(CheckpointError::Malformed(_))
        ));
    }

    #[test]
    fn concurrent_identical_append_publishes_once_and_reconciles_the_loser() {
        let directory = tempfile::tempdir().unwrap();
        let stores = [
            std::sync::Arc::new(open_store(&directory)),
            std::sync::Arc::new(open_store(&directory)),
        ];
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        for store in &stores {
            *store.publish_barrier.lock().unwrap() = Some(std::sync::Arc::clone(&barrier));
        }
        let expected = head(12, "66");

        let workers = stores
            .iter()
            .map(|store| {
                let store = std::sync::Arc::clone(store);
                let expected = expected.clone();
                std::thread::spawn(move || store.append(&expected).unwrap())
            })
            .collect::<Vec<_>>();
        let mut outcomes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        outcomes.sort_by_key(|outcome| match outcome {
            AppendOutcome::Appended => 0,
            AppendOutcome::AlreadyPresent => 1,
        });
        assert_eq!(
            outcomes,
            vec![AppendOutcome::Appended, AppendOutcome::AlreadyPresent]
        );
        let expected_suffix = checkpoint_filename(&expected);
        assert!(
            fs::read_dir(directory.path().parent().unwrap())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .all(|name| {
                    let name = name.to_string_lossy();
                    !name.starts_with(".bloom-checkpoint-") || !name.ends_with(&expected_suffix)
                })
        );

        drop(stores);
        let reopened = open_store(&directory);
        assert_eq!(
            reopened.append(&expected).unwrap(),
            AppendOutcome::AlreadyPresent
        );
    }

    #[test]
    fn one_recipient_serializes_concurrent_peer_head_advances() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let peers = [
            (
                "bloom-machine",
                "machine-app",
                SigningKey::from_bytes(&[11; 32]),
            ),
            (
                "bloom-broker",
                "broker-app",
                SigningKey::from_bytes(&[12; 32]),
            ),
            (
                "bloom-signer",
                "signer-app",
                SigningKey::from_bytes(&[13; 32]),
            ),
        ];
        let service_ids = ["bloom-machine", "bloom-broker", "bloom-signer"];
        let store = std::sync::Arc::new(
            CheckpointStore::open(
                directory.path(),
                uid,
                Token::new("bloom-broker").unwrap(),
                peers
                    .iter()
                    .map(|(service_id, key_id, signing_key)| PinnedAuditKey {
                        service_id: Token::new(*service_id).unwrap(),
                        key_id: Token::new(*key_id).unwrap(),
                        verifying_key: signing_key.verifying_key(),
                    }),
            )
            .unwrap(),
        );
        let start = std::sync::Arc::new(std::sync::Barrier::new(peers.len()));
        let workers = peers
            .into_iter()
            .enumerate()
            .map(|(peer_index, (service_id, key_id, signing_key))| {
                let store = std::sync::Arc::clone(&store);
                let start = std::sync::Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    for sequence in 1..=24 {
                        let hash_byte = format!("{:02x}", (sequence + peer_index as u64) % 255);
                        let mut head = SignedJournalHead {
                            service_id: Token::new(service_id).unwrap(),
                            sequence: DecimalU64::new(sequence),
                            head_hash: Digest32::new(hash_byte.repeat(32)).unwrap(),
                            key_id: Token::new(key_id).unwrap(),
                            signature: Base64UrlBytes::from_bytes(&[0; 64]),
                        };
                        head.signature = Base64UrlBytes::from_bytes(
                            &signing_key.sign(&head.signature_message()).to_bytes(),
                        );
                        store.append(&head).unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        for service_id in service_ids {
            assert_eq!(
                store
                    .latest(&Token::new(service_id).unwrap())
                    .unwrap()
                    .unwrap()
                    .sequence
                    .get(),
                24
            );
        }
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
    fn application_key_handover_is_exact_once_and_history_is_verification_only() {
        let directory = tempfile::tempdir().unwrap();
        let old_store = open_store(&directory);
        old_store.append(&head(7, "11")).unwrap();
        drop(old_store);

        let handover = ApplicationKeyHandover {
            service_id: Token::new("bloom-signer").unwrap(),
            old_key_id: Token::new("signer-audit-1").unwrap(),
            new_key_id: Token::new("signer-app-2").unwrap(),
            sequence: DecimalU64::new(7),
            head_hash: Digest32::new("11".repeat(32)).unwrap(),
        };
        let rotated = open_rotated_store(&directory, true, Some(handover.clone())).unwrap();
        let first_new = keyed_head(&rotated_signing_key(), "signer-app-2", 7, "11");
        assert_eq!(rotated.append(&first_new).unwrap(), AppendOutcome::Appended);
        assert_eq!(
            rotated.append(&first_new).unwrap(),
            AppendOutcome::AlreadyPresent
        );
        assert_eq!(
            rotated
                .append(&keyed_head(&rotated_signing_key(), "signer-app-2", 8, "22"))
                .unwrap(),
            AppendOutcome::Appended
        );
        assert!(matches!(
            rotated.append(&keyed_head(&signing_key(), "signer-audit-1", 9, "33")),
            Err(CheckpointError::InvalidSignature)
        ));

        drop(rotated);
        assert!(open_rotated_store(&directory, true, Some(handover)).is_ok());
        assert!(matches!(
            open_rotated_store(&directory, false, None),
            Err(CheckpointError::UnpinnedPeer)
        ));
    }

    #[test]
    fn handover_rejects_missing_substituted_rollback_and_equal_sequence_fork() {
        let scenarios = [
            (7, "22", 7, "11"), // equal-sequence hash fork
            (7, "11", 6, "11"), // packaging history rollback
            (7, "11", 7, "22"), // substituted tuple hash
        ];
        for (new_sequence, new_hash, tuple_sequence, tuple_hash) in scenarios {
            let directory = tempfile::tempdir().unwrap();
            let old_store = open_store(&directory);
            old_store.append(&head(7, "11")).unwrap();
            drop(old_store);
            let handover = ApplicationKeyHandover {
                service_id: Token::new("bloom-signer").unwrap(),
                old_key_id: Token::new("signer-audit-1").unwrap(),
                new_key_id: Token::new("signer-app-2").unwrap(),
                sequence: DecimalU64::new(tuple_sequence),
                head_hash: Digest32::new(tuple_hash.repeat(32)).unwrap(),
            };
            let rotated = open_rotated_store(&directory, true, Some(handover)).unwrap();
            assert!(matches!(
                rotated.append(&keyed_head(
                    &rotated_signing_key(),
                    "signer-app-2",
                    new_sequence,
                    new_hash
                )),
                Err(CheckpointError::SequenceConflict | CheckpointError::SequenceRollback)
            ));
        }
    }

    #[test]
    fn root_owned_authority_history_rejects_unsafe_or_substituted_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority-edge-history.json");
        let key_hex = hex::encode(signing_key().verifying_key().as_bytes());
        let document = serde_json::json!({
            "schema": "bloom.authority-edge-application-history.1",
            "historical_keys": [{
                "service_id": "bloom-signer",
                "key_id": "signer-audit-1",
                "public_key_hex": key_hex
            }],
            "handovers": []
        });
        fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let uid = fs::metadata(&path).unwrap().uid();
        let history = AuthorityEdgeHistory::load_trusted(&path, uid).unwrap();
        assert_eq!(
            history
                .historical_pins_for(&[&Token::new("bloom-signer").unwrap()])
                .unwrap()
                .len(),
            1
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(matches!(
            AuthorityEdgeHistory::load_trusted(&path, uid),
            Err(CheckpointError::Malformed(_))
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let hardlink = directory
            .path()
            .join("authority-edge-history-hardlink.json");
        fs::hard_link(&path, &hardlink).unwrap();
        assert!(matches!(
            AuthorityEdgeHistory::load_trusted(&path, uid),
            Err(CheckpointError::Malformed(_))
        ));
        fs::remove_file(&hardlink).unwrap();
        let target = directory.path().join("history-target.json");
        fs::rename(&path, &target).unwrap();
        symlink(&target, &path).unwrap();
        assert!(matches!(
            AuthorityEdgeHistory::load_trusted(&path, uid),
            Err(CheckpointError::Malformed(_))
        ));
    }

    #[test]
    fn authority_history_schema_and_public_keys_are_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority-edge-history.json");
        let uid = fs::metadata(directory.path()).unwrap().uid();
        for document in [
            serde_json::json!({
                "schema": "bloom.authority-edge-application-history.0",
                "historical_keys": [],
                "handovers": []
            }),
            serde_json::json!({
                "schema": "bloom.authority-edge-application-history.1",
                "historical_keys": [{
                    "service_id": "bloom-signer",
                    "key_id": "signer-audit-1",
                    "public_key_hex": "00"
                }],
                "handovers": []
            }),
        ] {
            fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            let history = AuthorityEdgeHistory::load_trusted(&path, uid);
            if document["schema"] == "bloom.authority-edge-application-history.0" {
                assert!(matches!(history, Err(CheckpointError::Malformed(_))));
            } else {
                assert!(matches!(
                    history
                        .unwrap()
                        .historical_pins_for(&[&Token::new("bloom-signer").unwrap()]),
                    Err(CheckpointError::Malformed(_))
                ));
            }
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
