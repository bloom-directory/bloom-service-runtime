use serde::{Deserialize, Serialize};

use crate::{Base64UrlBytes, BootEpoch, Digest32, ProtocolVersion, Token};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HelloChallenge {
    pub service_id: Token,
    pub boot_epoch: BootEpoch,
    pub protocol: ProtocolVersion,
    pub challenge: Digest32,
    pub application_key_id: Token,
    pub signature: Base64UrlBytes,
}
