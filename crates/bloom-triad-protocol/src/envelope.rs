use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use crate::{
    Base64UrlBytes, BootEpoch, DecimalU64, Digest32, OperationId, PROTOCOL_MAJOR,
    PROTOCOL_MINOR_MAX, PROTOCOL_MINOR_MIN, ProtocolError, ProtocolErrorCode, SignedJournalHead,
    Token,
};

pub const RPC_ENVELOPE_SCHEMA_V1: &str = "bloom.rpc-envelope.1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const CURRENT: Self = Self {
        major: PROTOCOL_MAJOR,
        minor: PROTOCOL_MINOR_MAX,
    };

    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.major != PROTOCOL_MAJOR
            || !(PROTOCOL_MINOR_MIN..=PROTOCOL_MINOR_MAX).contains(&self.minor)
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::UnsupportedVersion,
                format!(
                    "unsupported protocol {}.{}; supported {}.{}-{}",
                    self.major, self.minor, PROTOCOL_MAJOR, PROTOCOL_MINOR_MIN, PROTOCOL_MINOR_MAX
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    Request,
    Response,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedEnvelope<T> {
    pub protocol: ProtocolVersion,
    pub schema: Token,
    pub kind: EnvelopeKind,
    pub method: Token,
    pub operation_id: OperationId,
    pub request_digest: Digest32,
    pub caller_service_id: Token,
    pub caller_boot_epoch: BootEpoch,
    pub audience: Token,
    pub sent_at_ms: DecimalU64,
    pub deadline_ms: DecimalU64,
    pub body: T,
    pub application_key_id: Token,
    /// Independently signed sender audit head. Protocol minor 1 requires this
    /// on both authority edges (Machine-Broker and Broker-Signer) and forbids
    /// it on every other edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_journal_head: Option<SignedJournalHead>,
}

impl<T: Serialize> UnsignedEnvelope<T> {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        serde_jcs::to_vec(self).map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("envelope JCS encoding failed: {error}"),
            )
        })
    }

    pub fn expected_request_digest(&self) -> Result<Digest32, ProtocolError> {
        let body = serde_jcs::to_vec(&self.body).map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("request body JCS encoding failed: {error}"),
            )
        })?;
        Ok(Digest32::from_bytes(Sha256::digest(body).into()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: DeserializeOwned"))]
pub struct SignedEnvelope<T> {
    #[serde(flatten)]
    pub unsigned: UnsignedEnvelope<T>,
    pub signature: Base64UrlBytes,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedPeer {
    pub effective_uid: u32,
    pub service_id: Token,
    pub boot_epoch: BootEpoch,
    pub audience: Token,
    pub application_key_id: Token,
    pub application_public_key: [u8; 32],
}

/// A typed RPC body whose wire representation contains a closed method tag.
pub trait TypedRequestMethod: Serialize {
    fn method(&self) -> Result<Token, ProtocolError> {
        let value = serde_json::to_value(self).map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("typed request serialization failed: {error}"),
            )
        })?;
        let method = value
            .as_object()
            .and_then(|object| object.get("method"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::MalformedFrame,
                    "typed request has no method discriminator",
                )
            })?;
        Token::new(method)
    }

    /// Returns the stable domain operation ID when the typed request carries
    /// one directly. Read-only requests without an operation receive a fresh
    /// transport correlation ID from the caller.
    fn operation_id(&self) -> Result<Option<OperationId>, ProtocolError> {
        Ok(None)
    }
}

impl<T: Serialize> SignedEnvelope<T> {
    pub fn verify(
        &self,
        observed_effective_uid: u32,
        expected: &AuthenticatedPeer,
    ) -> Result<(), ProtocolError> {
        self.unsigned.protocol.validate()?;
        if self.unsigned.schema.as_str() != RPC_ENVELOPE_SCHEMA_V1 {
            return Err(ProtocolError::new(
                ProtocolErrorCode::UnsupportedVersion,
                "unsupported RPC envelope schema",
            ));
        }
        if observed_effective_uid != expected.effective_uid
            || self.unsigned.caller_service_id != expected.service_id
            || self.unsigned.caller_boot_epoch != expected.boot_epoch
            || self.unsigned.audience != expected.audience
            || self.unsigned.application_key_id != expected.application_key_id
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::UnauthenticatedPeer,
                "OS peer or pinned application identity mismatch",
            ));
        }
        if self.unsigned.deadline_ms.get() <= self.unsigned.sent_at_ms.get() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "envelope deadline must be after sent_at",
            ));
        }
        if self.unsigned.kind == EnvelopeKind::Request
            && self.unsigned.request_digest != self.unsigned.expected_request_digest()?
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "request digest does not match canonical body",
            ));
        }

        let verifying_key =
            VerifyingKey::from_bytes(&expected.application_public_key).map_err(|_| {
                ProtocolError::new(
                    ProtocolErrorCode::UnauthenticatedPeer,
                    "invalid pinned application public key",
                )
            })?;
        let signature_bytes: [u8; 64] = self.signature.decode().try_into().map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::UnauthenticatedPeer,
                "application signature must contain 64 bytes",
            )
        })?;
        verifying_key
            .verify(
                &self.unsigned.canonical_bytes()?,
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| {
                ProtocolError::new(
                    ProtocolErrorCode::UnauthenticatedPeer,
                    "application signature verification failed",
                )
            })?;

        self.verify_sender_journal_head(expected)
    }

    fn verify_sender_journal_head(
        &self,
        expected: &AuthenticatedPeer,
    ) -> Result<(), ProtocolError> {
        let authority_edge = is_authority_edge(
            self.unsigned.caller_service_id.as_str(),
            self.unsigned.audience.as_str(),
        );
        if self.unsigned.protocol.minor == 0 {
            if self.unsigned.sender_journal_head.is_some() || authority_edge {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::UnsupportedVersion,
                    "authority-edge journal heads require protocol minor 1 without downgrade",
                ));
            }
            return Ok(());
        }
        match (&self.unsigned.sender_journal_head, authority_edge) {
            (Some(head), true) => head.verify_sender_identity(
                &self.unsigned.caller_service_id,
                &self.unsigned.application_key_id,
                &expected.application_public_key,
            ),
            (None, true) => Err(ProtocolError::new(
                ProtocolErrorCode::UnauthenticatedPeer,
                "authority-edge envelope omitted its signed sender journal head",
            )),
            (Some(_), false) => Err(ProtocolError::new(
                ProtocolErrorCode::UnauthenticatedPeer,
                "sender journal heads are forbidden outside authority edges",
            )),
            (None, false) => Ok(()),
        }
    }

    /// Verifies a response and binds it to the exact authenticated request.
    pub fn verify_response_to<U: Serialize>(
        &self,
        observed_effective_uid: u32,
        expected: &AuthenticatedPeer,
        request: &SignedEnvelope<U>,
    ) -> Result<(), ProtocolError> {
        self.verify(observed_effective_uid, expected)?;
        if self.unsigned.kind != EnvelopeKind::Response
            || request.unsigned.kind != EnvelopeKind::Request
            || self.unsigned.method != request.unsigned.method
            || self.unsigned.operation_id != request.unsigned.operation_id
            || self.unsigned.request_digest != request.unsigned.request_digest
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "response does not correlate to the authenticated request",
            ));
        }
        Ok(())
    }
}

fn is_authority_edge(caller: &str, audience: &str) -> bool {
    matches!(
        (caller, audience),
        ("bloom-machine", "bloom-broker")
            | ("bloom-broker", "bloom-machine")
            | ("bloom-broker", "bloom-signer")
            | ("bloom-signer", "bloom-broker")
    )
}

impl<T: Serialize + TypedRequestMethod> SignedEnvelope<T> {
    /// Verifies peer/application identity and binds the authenticated outer
    /// method to the typed body's dispatch discriminator.
    pub fn verify_typed(
        &self,
        observed_effective_uid: u32,
        expected: &AuthenticatedPeer,
    ) -> Result<(), ProtocolError> {
        self.verify(observed_effective_uid, expected)?;
        if self.unsigned.kind != EnvelopeKind::Request {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "typed request verifier received a response envelope",
            ));
        }
        if self.unsigned.method != self.unsigned.body.method()? {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "authenticated envelope method does not match typed request method",
            ));
        }
        if self
            .unsigned
            .body
            .operation_id()?
            .is_some_and(|body_id| body_id != self.unsigned.operation_id)
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "authenticated envelope operation ID does not match typed request body",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[derive(Serialize)]
    #[serde(tag = "method", content = "body")]
    enum OperationRequestFixture {
        #[serde(rename = "test.mutate")]
        Mutate { operation_id: OperationId },
    }

    impl TypedRequestMethod for OperationRequestFixture {
        fn operation_id(&self) -> Result<Option<OperationId>, ProtocolError> {
            let Self::Mutate { operation_id } = self;
            Ok(Some(operation_id.clone()))
        }
    }

    fn journal_head(signing_key: &SigningKey, service: &str, key_id: &str) -> SignedJournalHead {
        let mut head = SignedJournalHead {
            service_id: Token::new(service).unwrap(),
            sequence: DecimalU64::new(7),
            head_hash: Digest32::from_bytes([9; 32]),
            key_id: Token::new(key_id).unwrap(),
            signature: Base64UrlBytes::from_bytes(&[]),
        };
        head.signature =
            Base64UrlBytes::from_bytes(&signing_key.sign(&head.signature_message()).to_bytes());
        head
    }

    fn signed() -> (SignedEnvelope<String>, AuthenticatedPeer) {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let body = "body".to_owned();
        let digest = Digest32::from_bytes(Sha256::digest(b"\"body\"").into());
        let unsigned = UnsignedEnvelope {
            protocol: ProtocolVersion::CURRENT,
            schema: Token::new("bloom.rpc-envelope.1").unwrap(),
            kind: EnvelopeKind::Request,
            method: Token::new("signer.sign").unwrap(),
            operation_id: OperationId::new("11".repeat(32)).unwrap(),
            request_digest: digest,
            caller_service_id: Token::new("bloom-broker").unwrap(),
            caller_boot_epoch: BootEpoch::new("22".repeat(16)).unwrap(),
            audience: Token::new("bloom-signer").unwrap(),
            sent_at_ms: DecimalU64::new(10),
            deadline_ms: DecimalU64::new(20),
            body,
            application_key_id: Token::new("broker-app-1").unwrap(),
            sender_journal_head: Some(journal_head(&signing_key, "bloom-broker", "broker-app-1")),
        };
        let signature = signing_key.sign(&unsigned.canonical_bytes().unwrap());
        let envelope = SignedEnvelope {
            unsigned,
            signature: Base64UrlBytes::from_bytes(&signature.to_bytes()),
        };
        let peer = AuthenticatedPeer {
            effective_uid: 501,
            service_id: Token::new("bloom-broker").unwrap(),
            boot_epoch: BootEpoch::new("22".repeat(16)).unwrap(),
            audience: Token::new("bloom-signer").unwrap(),
            application_key_id: Token::new("broker-app-1").unwrap(),
            application_public_key: signing_key.verifying_key().to_bytes(),
        };
        (envelope, peer)
    }

    #[test]
    fn typed_transport_operation_uses_the_stable_body_operation() {
        let operation_id = OperationId::from_bytes([44; 32]);
        let request = OperationRequestFixture::Mutate {
            operation_id: operation_id.clone(),
        };
        assert_eq!(request.operation_id().unwrap(), Some(operation_id));
    }

    #[test]
    fn typed_verifier_rejects_outer_and_body_operation_mismatch() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let body = OperationRequestFixture::Mutate {
            operation_id: OperationId::from_bytes([44; 32]),
        };
        let unsigned = UnsignedEnvelope {
            protocol: ProtocolVersion::CURRENT,
            schema: Token::new(RPC_ENVELOPE_SCHEMA_V1).unwrap(),
            kind: EnvelopeKind::Request,
            method: body.method().unwrap(),
            operation_id: OperationId::from_bytes([45; 32]),
            request_digest: Digest32::from_bytes(
                Sha256::digest(serde_jcs::to_vec(&body).unwrap()).into(),
            ),
            caller_service_id: Token::new("bloom-machine").unwrap(),
            caller_boot_epoch: BootEpoch::from_bytes([2; 16]),
            audience: Token::new("bloom-broker").unwrap(),
            sent_at_ms: DecimalU64::new(10),
            deadline_ms: DecimalU64::new(20),
            body,
            application_key_id: Token::new("machine-app").unwrap(),
            sender_journal_head: Some(journal_head(&signing_key, "bloom-machine", "machine-app")),
        };
        let envelope = SignedEnvelope {
            signature: Base64UrlBytes::from_bytes(
                &signing_key
                    .sign(&unsigned.canonical_bytes().unwrap())
                    .to_bytes(),
            ),
            unsigned,
        };
        let expected = AuthenticatedPeer {
            effective_uid: 501,
            service_id: Token::new("bloom-machine").unwrap(),
            boot_epoch: BootEpoch::from_bytes([2; 16]),
            audience: Token::new("bloom-broker").unwrap(),
            application_key_id: Token::new("machine-app").unwrap(),
            application_public_key: signing_key.verifying_key().to_bytes(),
        };
        assert_eq!(
            envelope.verify_typed(501, &expected).unwrap_err().code,
            ProtocolErrorCode::OperationIdConflict
        );
    }

    #[test]
    fn dual_peer_identity_and_all_envelope_bindings_fail_closed() {
        let (envelope, peer) = signed();
        envelope.verify(501, &peer).unwrap();
        assert_eq!(
            envelope.verify(502, &peer).unwrap_err().code,
            ProtocolErrorCode::UnauthenticatedPeer
        );

        let mut wrong = envelope.clone();
        wrong.unsigned.audience = Token::new("bloom-machine").unwrap();
        assert_eq!(
            wrong.verify(501, &peer).unwrap_err().code,
            ProtocolErrorCode::UnauthenticatedPeer
        );

        let mut wrong = envelope.clone();
        wrong.unsigned.protocol.major = 2;
        assert_eq!(
            wrong.verify(501, &peer).unwrap_err().code,
            ProtocolErrorCode::UnsupportedVersion
        );

        let mut wrong = envelope;
        wrong.unsigned.body = "changed".into();
        assert_eq!(
            wrong.verify(501, &peer).unwrap_err().code,
            ProtocolErrorCode::MalformedFrame
        );
    }
}
