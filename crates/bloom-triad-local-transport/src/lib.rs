//! Authenticated, bounded local transport shared by the three Bloom services.

#![forbid(unsafe_code)]
#![cfg(unix)]

use std::{
    collections::VecDeque,
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use bloom_triad_protocol::{
    AuthenticatedPeer, Base64UrlBytes, BootEpoch, BrokerSignerRequest, BrokerSignerResponse,
    BrokerSignerService, ControlRequest, ControlResponse, DecimalU64, Digest32, EnvelopeKind,
    HelloChallenge, MachineBrokerRequest, MachineBrokerResponse, MachineBrokerService, OperationId,
    ProtocolError, ProtocolErrorCode, ProtocolVersion, RPC_ENVELOPE_SCHEMA_V1,
    RevocationControlService, SignedEnvelope, Token, TypedRequestMethod, UnsignedEnvelope,
    decode_frame, encode_frame,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::{OwnedSemaphorePermit, Semaphore},
};

const HELLO_DOMAIN: &[u8] = b"bloom-local-hello/v1";
const FRAME_MAX_BYTES: usize = 1024 * 1024;

pub struct EndpointQuota {
    mutation_slots: Arc<Semaphore>,
    request_rate: std::sync::Mutex<SlidingAdmission>,
    journal_rate: std::sync::Mutex<SlidingAdmission>,
}

struct SlidingAdmission {
    maximum: usize,
    window_ms: u64,
    accepted_at_ms: VecDeque<u64>,
}

#[derive(Debug)]
pub struct EndpointAdmission {
    _mutation_permit: Option<OwnedSemaphorePermit>,
}

impl EndpointQuota {
    pub fn new(
        maximum_in_flight_mutations: usize,
        maximum_requests_per_window: usize,
        request_window_ms: u64,
        maximum_journal_admissions_per_window: usize,
        journal_window_ms: u64,
    ) -> Result<Self, ProtocolError> {
        if maximum_in_flight_mutations == 0
            || maximum_requests_per_window == 0
            || request_window_ms == 0
            || maximum_journal_admissions_per_window == 0
            || journal_window_ms == 0
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "endpoint quota values must be nonzero",
            ));
        }
        Ok(Self {
            mutation_slots: Arc::new(Semaphore::new(maximum_in_flight_mutations)),
            request_rate: std::sync::Mutex::new(SlidingAdmission {
                maximum: maximum_requests_per_window,
                window_ms: request_window_ms,
                accepted_at_ms: VecDeque::new(),
            }),
            journal_rate: std::sync::Mutex::new(SlidingAdmission {
                maximum: maximum_journal_admissions_per_window,
                window_ms: journal_window_ms,
                accepted_at_ms: VecDeque::new(),
            }),
        })
    }

    pub fn admit(
        &self,
        method: &Token,
        observed_at_ms: u64,
    ) -> Result<EndpointAdmission, ProtocolError> {
        self.request_rate
            .lock()
            .map_err(|_| unavailable("request rate gate poisoned".into()))?
            .admit(observed_at_ms, "request rate quota exhausted")?;
        if is_read_method(method.as_str()) {
            return Ok(EndpointAdmission {
                _mutation_permit: None,
            });
        }
        let permit = self
            .mutation_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                ProtocolError::new(
                    ProtocolErrorCode::QuotaExceeded,
                    "concurrent mutation quota exhausted",
                )
            })?;
        self.journal_rate
            .lock()
            .map_err(|_| unavailable("journal admission gate poisoned".into()))?
            .admit(
                observed_at_ms,
                "operation journal admission quota exhausted",
            )?;
        Ok(EndpointAdmission {
            _mutation_permit: Some(permit),
        })
    }
}

impl SlidingAdmission {
    fn admit(&mut self, now_ms: u64, message: &str) -> Result<(), ProtocolError> {
        while self
            .accepted_at_ms
            .front()
            .is_some_and(|accepted| accepted.saturating_add(self.window_ms) <= now_ms)
        {
            self.accepted_at_ms.pop_front();
        }
        if self.accepted_at_ms.len() >= self.maximum {
            return Err(ProtocolError::new(
                ProtocolErrorCode::QuotaExceeded,
                message,
            ));
        }
        self.accepted_at_ms.push_back(now_ms);
        Ok(())
    }
}

fn is_read_method(method: &str) -> bool {
    method.ends_with(".read")
        || method.ends_with(".readiness")
        || method.ends_with(".capabilities")
        || method.ends_with(".status")
        || method.ends_with(".list")
        || method.ends_with(".list_public")
        || method.ends_with(".get_public")
        || method == "revocation.state"
        || method == "sealed_approval.limit_state"
        || method == "key.derivation_capabilities"
        || method == "key.list_derived"
        || method == "credential.list_public"
        || method == "custody.result"
}

#[derive(Clone)]
pub struct LocalIdentity {
    pub service_id: Token,
    pub boot_epoch: BootEpoch,
    pub application_key_id: Token,
    pub signing_key: Arc<SigningKey>,
}

#[derive(Clone)]
pub struct PeerAcl {
    pub effective_uid: u32,
    pub service_id: Token,
    pub boot_epoch: BootEpoch,
    pub application_key_id: Token,
    pub application_public_key: [u8; 32],
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeManifest {
    pub schema: String,
    pub machine: ManifestPeer,
    pub broker: ManifestPeer,
    pub signer: ManifestPeer,
    pub revoke_client: ManifestPeer,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPeer {
    pub effective_uid: u32,
    pub service_id: String,
    pub boot_epoch: String,
    pub application_key_id: String,
    pub application_public_key_hex: String,
}

impl ManifestPeer {
    pub fn into_acl(self) -> Result<PeerAcl, ProtocolError> {
        Ok(PeerAcl {
            effective_uid: self.effective_uid,
            service_id: Token::new(self.service_id)?,
            boot_epoch: BootEpoch::new(self.boot_epoch)?,
            application_key_id: Token::new(self.application_key_id)?,
            application_public_key: hex::decode(self.application_public_key_hex)
                .map_err(|_| unauthenticated("manifest application public key is not hexadecimal"))?
                .try_into()
                .map_err(|_| {
                    unauthenticated("manifest application public key must contain 32 bytes")
                })?,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFile {
    service_id: String,
    boot_epoch: String,
    application_key_id: String,
    private_key_seed_hex: String,
}

pub fn load_identity_and_manifest(
    identity_path: &Path,
    manifest_path: &Path,
    expected_service_id: &str,
) -> Result<(LocalIdentity, EdgeManifest), ProtocolError> {
    require_private_identity_permissions(identity_path)?;
    require_root_manifest_permissions(manifest_path)?;
    let identity_file: IdentityFile = decode_security_file(identity_path)?;
    let manifest: EdgeManifest = decode_security_file(manifest_path)?;
    if manifest.schema != "bloom.edge-manifest.1" {
        return Err(ProtocolError::new(
            ProtocolErrorCode::UnsupportedVersion,
            "unsupported edge manifest schema",
        ));
    }
    let identity = identity_file.into_identity()?;
    if identity.service_id.as_str() != expected_service_id {
        return Err(unauthenticated(
            "application identity file has the wrong service ID",
        ));
    }
    let pinned = match expected_service_id {
        "bloom-machine" => manifest.machine.clone(),
        "bloom-broker" => manifest.broker.clone(),
        "bloom-signer" => manifest.signer.clone(),
        _ => return Err(unauthenticated("unknown local service identity")),
    }
    .into_acl()?;
    if pinned.service_id != identity.service_id
        || pinned.boot_epoch != identity.boot_epoch
        || pinned.application_key_id != identity.application_key_id
        || pinned.application_public_key != identity.signing_key.verifying_key().to_bytes()
    {
        return Err(unauthenticated(
            "application identity does not match the pinned edge manifest",
        ));
    }
    Ok((identity, manifest))
}

impl IdentityFile {
    fn into_identity(self) -> Result<LocalIdentity, ProtocolError> {
        let mut seed: [u8; 32] = hex::decode(self.private_key_seed_hex)
            .map_err(|_| unauthenticated("identity seed is not hexadecimal"))?
            .try_into()
            .map_err(|_| unauthenticated("identity seed must contain 32 bytes"))?;
        let signing_key = SigningKey::from_bytes(&seed);
        seed.fill(0);
        Ok(LocalIdentity {
            service_id: Token::new(self.service_id)?,
            boot_epoch: BootEpoch::new(self.boot_epoch)?,
            application_key_id: Token::new(self.application_key_id)?,
            signing_key: Arc::new(signing_key),
        })
    }
}

impl PeerAcl {
    pub fn authenticated_for(&self, audience: Token) -> AuthenticatedPeer {
        AuthenticatedPeer {
            effective_uid: self.effective_uid,
            service_id: self.service_id.clone(),
            boot_epoch: self.boot_epoch.clone(),
            audience,
            application_key_id: self.application_key_id.clone(),
            application_public_key: self.application_public_key,
        }
    }
}

pub async fn authenticate_client(
    stream: &mut UnixStream,
    identity: &LocalIdentity,
    broker: &PeerAcl,
) -> Result<(), ProtocolError> {
    require_peer_uid(stream, broker.effective_uid)?;
    let server_challenge: HelloChallenge = read_frame(stream).await?;
    verify_hello(&server_challenge, broker)?;
    write_frame(
        stream,
        &signed_hello(identity, server_challenge.challenge.clone())?,
    )
    .await?;

    let client_challenge = random_digest();
    write_frame(stream, &signed_hello(identity, client_challenge.clone())?).await?;
    let server_response: HelloChallenge = read_frame(stream).await?;
    verify_hello(&server_response, broker)?;
    if server_response.challenge != client_challenge {
        return Err(unauthenticated(
            "Broker did not answer Machine's fresh challenge",
        ));
    }
    Ok(())
}

pub async fn authenticate_server(
    stream: &mut UnixStream,
    identity: &LocalIdentity,
    client: &PeerAcl,
) -> Result<(), ProtocolError> {
    require_peer_uid(stream, client.effective_uid)?;
    let server_challenge = random_digest();
    write_frame(stream, &signed_hello(identity, server_challenge.clone())?).await?;
    let client_response: HelloChallenge = read_frame(stream).await?;
    verify_hello(&client_response, client)?;
    if client_response.challenge != server_challenge {
        return Err(unauthenticated(
            "client did not answer server's fresh challenge",
        ));
    }

    let client_challenge: HelloChallenge = read_frame(stream).await?;
    verify_hello(&client_challenge, client)?;
    write_frame(
        stream,
        &signed_hello(identity, client_challenge.challenge.clone())?,
    )
    .await
}

pub fn sign_request<T>(
    identity: &LocalIdentity,
    audience: Token,
    operation_id: OperationId,
    body: T,
    sent_at_ms: u64,
    deadline_ms: u64,
) -> Result<SignedEnvelope<T>, ProtocolError>
where
    T: Clone + Serialize + TypedRequestMethod,
{
    let request_digest = digest(&body)?;
    let unsigned = UnsignedEnvelope {
        protocol: ProtocolVersion::CURRENT,
        schema: Token::new(RPC_ENVELOPE_SCHEMA_V1)?,
        kind: EnvelopeKind::Request,
        method: body.method()?,
        operation_id,
        request_digest,
        caller_service_id: identity.service_id.clone(),
        caller_boot_epoch: identity.boot_epoch.clone(),
        audience,
        sent_at_ms: DecimalU64::new(sent_at_ms),
        deadline_ms: DecimalU64::new(deadline_ms),
        body,
        application_key_id: identity.application_key_id.clone(),
    };
    let signature = identity.signing_key.sign(&unsigned.canonical_bytes()?);
    Ok(SignedEnvelope {
        unsigned,
        signature: Base64UrlBytes::from_bytes(&signature.to_bytes()),
    })
}

pub fn sign_response<T, U>(
    identity: &LocalIdentity,
    request: &SignedEnvelope<U>,
    body: T,
    sent_at_ms: u64,
    deadline_ms: u64,
) -> Result<SignedEnvelope<T>, ProtocolError>
where
    T: Serialize,
    U: Serialize,
{
    let unsigned = UnsignedEnvelope {
        protocol: ProtocolVersion::CURRENT,
        schema: Token::new(RPC_ENVELOPE_SCHEMA_V1)?,
        kind: EnvelopeKind::Response,
        method: request.unsigned.method.clone(),
        operation_id: request.unsigned.operation_id.clone(),
        request_digest: request.unsigned.request_digest.clone(),
        caller_service_id: identity.service_id.clone(),
        caller_boot_epoch: identity.boot_epoch.clone(),
        audience: request.unsigned.caller_service_id.clone(),
        sent_at_ms: DecimalU64::new(sent_at_ms),
        deadline_ms: DecimalU64::new(deadline_ms),
        body,
        application_key_id: identity.application_key_id.clone(),
    };
    let signature = identity.signing_key.sign(&unsigned.canonical_bytes()?);
    Ok(SignedEnvelope {
        unsigned,
        signature: Base64UrlBytes::from_bytes(&signature.to_bytes()),
    })
}

pub async fn call<T, U>(
    stream: &mut UnixStream,
    identity: &LocalIdentity,
    server: &PeerAcl,
    body: T,
    timeout_ms: u64,
) -> Result<U, ProtocolError>
where
    T: Clone + Serialize + TypedRequestMethod,
    U: Serialize + DeserializeOwned,
{
    authenticate_client(stream, identity, server).await?;
    let observed_uid = peer_uid(stream)?;
    let sent_at_ms = now_ms()?;
    let operation_id = body.operation_id()?.unwrap_or_else(random_operation_id);
    let request = sign_request(
        identity,
        server.service_id.clone(),
        operation_id,
        body,
        sent_at_ms,
        sent_at_ms.saturating_add(timeout_ms),
    )?;
    write_frame(stream, &request).await?;

    let response: SignedEnvelope<Result<U, ProtocolError>> = read_frame(stream).await?;
    response.verify_response_to(
        observed_uid,
        &server.authenticated_for(identity.service_id.clone()),
        &request,
    )?;
    require_live_deadline(&response, now_ms()?)?;
    response.unsigned.body
}

pub async fn receive_request<T>(
    stream: &mut UnixStream,
    identity: &LocalIdentity,
    client: &PeerAcl,
) -> Result<SignedEnvelope<T>, ProtocolError>
where
    T: Serialize + DeserializeOwned + TypedRequestMethod,
{
    authenticate_server(stream, identity, client).await?;
    let observed_uid = peer_uid(stream)?;
    let request: SignedEnvelope<T> = read_frame(stream).await?;
    request.verify_typed(
        observed_uid,
        &client.authenticated_for(identity.service_id.clone()),
    )?;
    require_live_deadline(&request, now_ms()?)?;
    Ok(request)
}

pub async fn send_response<T, U>(
    stream: &mut UnixStream,
    identity: &LocalIdentity,
    request: &SignedEnvelope<T>,
    response: Result<U, ProtocolError>,
) -> Result<(), ProtocolError>
where
    T: Serialize,
    U: Serialize,
{
    let sent_at_ms = now_ms()?;
    if sent_at_ms >= request.unsigned.deadline_ms.get() {
        return Err(ProtocolError::new(
            ProtocolErrorCode::ServiceUnavailable,
            "request deadline expired before response",
        ));
    }
    let envelope = sign_response(
        identity,
        request,
        response,
        sent_at_ms,
        request.unsigned.deadline_ms.get(),
    )?;
    write_frame(stream, &envelope).await
}

pub async fn dispatch_machine_broker_connection(
    stream: &mut UnixStream,
    identity: &LocalIdentity,
    machine: &PeerAcl,
    quota: &EndpointQuota,
    service: &dyn MachineBrokerService,
) -> Result<(), ProtocolError> {
    let request = receive_request::<MachineBrokerRequest>(stream, identity, machine).await?;
    let admission = match quota.admit(&request.unsigned.method, now_ms()?) {
        Ok(admission) => admission,
        Err(error) => {
            return send_response::<_, MachineBrokerResponse>(
                stream,
                identity,
                &request,
                Err(error),
            )
            .await;
        }
    };
    let result = service.dispatch(request.unsigned.body.clone()).await;
    drop(admission);
    send_response::<_, MachineBrokerResponse>(stream, identity, &request, result).await
}

pub async fn dispatch_broker_signer_connection(
    stream: &mut UnixStream,
    identity: &LocalIdentity,
    broker: &PeerAcl,
    quota: &EndpointQuota,
    service: &dyn BrokerSignerService,
) -> Result<(), ProtocolError> {
    let request = receive_request::<BrokerSignerRequest>(stream, identity, broker).await?;
    let admission = match quota.admit(&request.unsigned.method, now_ms()?) {
        Ok(admission) => admission,
        Err(error) => {
            return send_response::<_, BrokerSignerResponse>(
                stream,
                identity,
                &request,
                Err(error),
            )
            .await;
        }
    };
    let result = service.dispatch(request.unsigned.body.clone()).await;
    drop(admission);
    send_response::<_, BrokerSignerResponse>(stream, identity, &request, result).await
}

pub async fn dispatch_control_connection(
    stream: &mut UnixStream,
    identity: &LocalIdentity,
    revoke_client: &PeerAcl,
    quota: &EndpointQuota,
    service: &dyn RevocationControlService,
) -> Result<(), ProtocolError> {
    let request = receive_request::<ControlRequest>(stream, identity, revoke_client).await?;
    let admission = match quota.admit(&request.unsigned.method, now_ms()?) {
        Ok(admission) => admission,
        Err(error) => {
            return send_response::<_, ControlResponse>(stream, identity, &request, Err(error))
                .await;
        }
    };
    let result = service.dispatch(request.unsigned.body.clone()).await;
    drop(admission);
    send_response::<_, ControlResponse>(stream, identity, &request, result).await
}

pub async fn write_frame<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
) -> Result<(), ProtocolError> {
    let frame = encode_frame(value)?;
    stream
        .write_all(&frame)
        .await
        .map_err(|error| unavailable(format!("write local frame: {error}")))
}

pub async fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T, ProtocolError> {
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|error| unavailable(format!("read local frame prefix: {error}")))?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > FRAME_MAX_BYTES {
        return Err(ProtocolError::new(
            ProtocolErrorCode::LimitExceededFrame,
            "local frame exceeds 1 MiB",
        ));
    }
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|error| unavailable(format!("read local frame payload: {error}")))?;
    let mut frame = prefix.to_vec();
    frame.extend_from_slice(&payload);
    decode_frame(&frame)
}

fn signed_hello(
    identity: &LocalIdentity,
    challenge: Digest32,
) -> Result<HelloChallenge, ProtocolError> {
    let mut hello = HelloChallenge {
        service_id: identity.service_id.clone(),
        boot_epoch: identity.boot_epoch.clone(),
        protocol: ProtocolVersion::CURRENT,
        challenge,
        application_key_id: identity.application_key_id.clone(),
        signature: Base64UrlBytes::from_bytes(&[]),
    };
    let message = hello_message(&hello)?;
    hello.signature = Base64UrlBytes::from_bytes(&identity.signing_key.sign(&message).to_bytes());
    Ok(hello)
}

fn verify_hello(hello: &HelloChallenge, expected: &PeerAcl) -> Result<(), ProtocolError> {
    hello.protocol.validate()?;
    if hello.service_id != expected.service_id
        || hello.boot_epoch != expected.boot_epoch
        || hello.application_key_id != expected.application_key_id
    {
        return Err(unauthenticated(
            "hello service, boot epoch, or app key mismatch",
        ));
    }
    let key = VerifyingKey::from_bytes(&expected.application_public_key)
        .map_err(|_| unauthenticated("pinned application public key is invalid"))?;
    let signature: [u8; 64] = hello
        .signature
        .decode()
        .try_into()
        .map_err(|_| unauthenticated("hello signature must contain 64 bytes"))?;
    key.verify(&hello_message(hello)?, &Signature::from_bytes(&signature))
        .map_err(|_| unauthenticated("hello application signature is invalid"))
}

fn hello_message(hello: &HelloChallenge) -> Result<Vec<u8>, ProtocolError> {
    let mut unsigned = hello.clone();
    unsigned.signature = Base64UrlBytes::from_bytes(&[]);
    let mut message = HELLO_DOMAIN.to_vec();
    message.extend(serde_jcs::to_vec(&unsigned).map_err(|error| {
        ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
    })?);
    Ok(message)
}

fn require_peer_uid(stream: &UnixStream, expected: u32) -> Result<(), ProtocolError> {
    let observed = peer_uid(stream)?;
    if observed != expected {
        return Err(unauthenticated("OS peer effective UID is not allowed"));
    }
    Ok(())
}

fn peer_uid(stream: &UnixStream) -> Result<u32, ProtocolError> {
    Ok(stream
        .peer_cred()
        .map_err(|error| unavailable(format!("read local peer credentials: {error}")))?
        .uid())
}

fn random_digest() -> Digest32 {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Digest32::from_bytes(bytes)
}

fn random_operation_id() -> OperationId {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    OperationId::from_bytes(bytes)
}

fn now_ms() -> Result<u64, ProtocolError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::ClockRollback,
                "system time predates Unix epoch",
            )
        })?
        .as_millis();
    u64::try_from(millis).map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCode::ClockUntrusted,
            "system time is out of range",
        )
    })
}

fn require_live_deadline<T>(
    envelope: &SignedEnvelope<T>,
    observed_at_ms: u64,
) -> Result<(), ProtocolError> {
    if envelope.unsigned.deadline_ms.get() <= observed_at_ms {
        return Err(ProtocolError::new(
            ProtocolErrorCode::ServiceUnavailable,
            "authenticated local request deadline expired",
        ));
    }
    Ok(())
}

fn decode_security_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ProtocolError> {
    let bytes = fs::read(path)
        .map_err(|error| unauthenticated(&format!("read {}: {error}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| unauthenticated(&format!("parse {}: {error}", path.display())))
}

fn require_private_identity_permissions(path: &Path) -> Result<(), ProtocolError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| unauthenticated(&format!("inspect {}: {error}", path.display())))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o077 != 0
    {
        return Err(unauthenticated(
            "application identity must be a regular non-symlink file with mode 0600 or stricter",
        ));
    }
    Ok(())
}

fn require_root_manifest_permissions(path: &Path) -> Result<(), ProtocolError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| unauthenticated(&format!("inspect {}: {error}", path.display())))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(unauthenticated(
            "edge manifest must be a root-owned, non-symlink file not writable by group or other",
        ));
    }
    Ok(())
}

fn digest<T: Serialize>(value: &T) -> Result<Digest32, ProtocolError> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| {
        ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
    })?;
    Ok(Digest32::from_bytes(Sha256::digest(bytes).into()))
}

fn unauthenticated(message: &str) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::UnauthenticatedPeer, message)
}

fn unavailable(message: String) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(name: &str, key_byte: u8) -> LocalIdentity {
        LocalIdentity {
            service_id: Token::new(name).unwrap(),
            boot_epoch: BootEpoch::from_bytes([key_byte; 16]),
            application_key_id: Token::new(format!("{name}-app")).unwrap(),
            signing_key: Arc::new(SigningKey::from_bytes(&[key_byte; 32])),
        }
    }

    fn acl(identity: &LocalIdentity, uid: u32) -> PeerAcl {
        PeerAcl {
            effective_uid: uid,
            service_id: identity.service_id.clone(),
            boot_epoch: identity.boot_epoch.clone(),
            application_key_id: identity.application_key_id.clone(),
            application_public_key: identity.signing_key.verifying_key().to_bytes(),
        }
    }

    #[tokio::test]
    async fn mutual_challenge_and_uid_acl_succeed() {
        let (mut machine_stream, mut broker_stream) = UnixStream::pair().unwrap();
        let uid = machine_stream.peer_cred().unwrap().uid();
        let machine = identity("bloom-machine", 1);
        let broker = identity("bloom-broker", 2);
        let machine_acl = acl(&machine, uid);
        let broker_acl = acl(&broker, uid);
        let (client, server) = tokio::join!(
            authenticate_client(&mut machine_stream, &machine, &broker_acl),
            authenticate_server(&mut broker_stream, &broker, &machine_acl)
        );
        client.unwrap();
        server.unwrap();
    }

    #[tokio::test]
    async fn wrong_application_key_fails_closed() {
        let (mut machine_stream, mut broker_stream) = UnixStream::pair().unwrap();
        let uid = machine_stream.peer_cred().unwrap().uid();
        let machine = identity("bloom-machine", 1);
        let broker = identity("bloom-broker", 2);
        let machine_acl = acl(&machine, uid);
        let mut wrong_broker_acl = acl(&broker, uid);
        wrong_broker_acl.application_public_key =
            SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let server = tokio::spawn(async move {
            authenticate_server(&mut broker_stream, &broker, &machine_acl).await
        });
        let client = authenticate_client(&mut machine_stream, &machine, &wrong_broker_acl).await;
        assert_eq!(
            client.unwrap_err().code,
            ProtocolErrorCode::UnauthenticatedPeer
        );
        drop(machine_stream);
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn wrong_effective_uid_fails_before_application_authentication() {
        let (mut machine_stream, mut broker_stream) = UnixStream::pair().unwrap();
        let observed_uid = machine_stream.peer_cred().unwrap().uid();
        let wrong_uid = observed_uid.checked_add(1).unwrap_or_else(|| {
            observed_uid
                .checked_sub(1)
                .expect("a uid has an adjacent representable value")
        });
        let machine = identity("bloom-machine", 1);
        let broker = identity("bloom-broker", 2);
        let machine_acl = acl(&machine, wrong_uid);
        let broker_acl = acl(&broker, wrong_uid);

        let (client, server) = tokio::join!(
            authenticate_client(&mut machine_stream, &machine, &broker_acl),
            authenticate_server(&mut broker_stream, &broker, &machine_acl)
        );
        assert_eq!(
            client.unwrap_err().code,
            ProtocolErrorCode::UnauthenticatedPeer
        );
        assert_eq!(
            server.unwrap_err().code,
            ProtocolErrorCode::UnauthenticatedPeer
        );
    }

    #[tokio::test]
    async fn machine_cannot_authenticate_to_signer_endpoint() {
        let (mut machine_stream, mut signer_stream) = UnixStream::pair().unwrap();
        let uid = machine_stream.peer_cred().unwrap().uid();
        let machine = identity("bloom-machine", 1);
        let broker = identity("bloom-broker", 2);
        let signer = identity("bloom-signer", 3);
        let broker_acl = acl(&broker, uid);
        let signer_acl = acl(&signer, uid);

        let server = tokio::spawn(async move {
            authenticate_server(&mut signer_stream, &signer, &broker_acl).await
        });
        assert!(
            authenticate_client(&mut machine_stream, &machine, &signer_acl)
                .await
                .is_err()
        );
        drop(machine_stream);
        assert_eq!(
            server.await.unwrap().unwrap_err().code,
            ProtocolErrorCode::UnauthenticatedPeer
        );
    }

    #[tokio::test]
    async fn response_never_extends_an_expired_request_deadline() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let machine = identity("bloom-machine", 1);
        let broker = identity("bloom-broker", 2);
        let request = sign_request(
            &machine,
            broker.service_id.clone(),
            OperationId::from_bytes([4; 32]),
            bloom_triad_protocol::MachineBrokerRequest::ActionValidate(Digest32::from_bytes(
                [5; 32],
            )),
            1,
            2,
        )
        .unwrap();
        let error = send_response(
            &mut server,
            &broker,
            &request,
            Ok::<_, ProtocolError>(bloom_triad_protocol::MachineBrokerResponse::ActionValidate(
                Digest32::from_bytes([5; 32]),
            )),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::ServiceUnavailable);
        drop(client);
    }

    #[test]
    fn read_status_remains_available_while_mutation_quota_is_exhausted() {
        let quota = EndpointQuota::new(1, 10, 1_000, 10, 1_000).unwrap();
        let mutation = quota
            .admit(&Token::new("signer.sign").unwrap(), 100)
            .unwrap();
        assert_eq!(
            quota
                .admit(&Token::new("signer.sign").unwrap(), 101)
                .unwrap_err()
                .code,
            ProtocolErrorCode::QuotaExceeded
        );
        quota
            .admit(&Token::new("operation.status").unwrap(), 102)
            .unwrap();
        drop(mutation);
        quota
            .admit(&Token::new("signer.sign").unwrap(), 103)
            .unwrap();
    }

    #[test]
    fn endpoint_request_and_journal_windows_fail_closed_independently() {
        let request_limited = EndpointQuota::new(2, 1, 100, 10, 100).unwrap();
        request_limited
            .admit(&Token::new("operation.status").unwrap(), 10)
            .unwrap();
        assert_eq!(
            request_limited
                .admit(&Token::new("operation.status").unwrap(), 11)
                .unwrap_err()
                .code,
            ProtocolErrorCode::QuotaExceeded
        );
        request_limited
            .admit(&Token::new("operation.status").unwrap(), 110)
            .unwrap();

        let journal_limited = EndpointQuota::new(2, 10, 100, 1, 100).unwrap();
        let first = journal_limited
            .admit(&Token::new("signer.sign").unwrap(), 20)
            .unwrap();
        drop(first);
        assert_eq!(
            journal_limited
                .admit(&Token::new("signer.sign").unwrap(), 21)
                .unwrap_err()
                .code,
            ProtocolErrorCode::QuotaExceeded
        );
    }
}
