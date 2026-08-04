use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
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

    /// Verifies that this head was produced by the authenticated envelope
    /// sender using the application identity pinned for that transport edge.
    pub fn verify_sender_identity(
        &self,
        service_id: &Token,
        application_key_id: &Token,
        application_public_key: &[u8; 32],
    ) -> Result<(), crate::WireError> {
        if &self.service_id != service_id || &self.key_id != application_key_id {
            return Err(crate::WireError::new(
                crate::WireErrorCode::UnauthenticatedPeer,
                "journal head service or application key identity mismatch",
            ));
        }
        let verifying_key = VerifyingKey::from_bytes(application_public_key).map_err(|_| {
            crate::WireError::new(
                crate::WireErrorCode::UnauthenticatedPeer,
                "invalid pinned journal-head public key",
            )
        })?;
        let signature: [u8; 64] = self.signature.decode().try_into().map_err(|_| {
            crate::WireError::new(
                crate::WireErrorCode::UnauthenticatedPeer,
                "journal-head signature must contain 64 bytes",
            )
        })?;
        verifying_key
            .verify(
                &self.signature_message(),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| {
                crate::WireError::new(
                    crate::WireErrorCode::UnauthenticatedPeer,
                    "journal-head application signature verification failed",
                )
            })
    }
}
