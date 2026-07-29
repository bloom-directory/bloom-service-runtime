use serde::{Deserialize, Serialize};

use crate::{Base64UrlBytes, DecimalU64, Digest32, Token};

/// A service-signed audit-journal head exchanged with a peer or checkpointed
/// by a recipient. Signature verification is performed with the edge-manifest
/// key pinned for `service_id`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedJournalHead {
    pub service_id: Token,
    pub sequence: DecimalU64,
    pub head_hash: Digest32,
    pub key_id: Token,
    pub signature: Base64UrlBytes,
}

impl SignedJournalHead {
    pub fn signature_message(&self) -> Vec<u8> {
        let mut message = b"bloom-audit-journal-head/v1\0".to_vec();
        message.extend_from_slice(self.service_id.as_str().as_bytes());
        message.push(0);
        message.extend_from_slice(&self.sequence.get().to_be_bytes());
        message.extend_from_slice(self.head_hash.as_str().as_bytes());
        message.push(0);
        message.extend_from_slice(self.key_id.as_str().as_bytes());
        message
    }
}
