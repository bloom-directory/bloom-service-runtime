use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{WireError, WireErrorCode};

pub const FRAME_MAX_BYTES: usize = 1024 * 1024;
pub const JSON_MAX_DEPTH: usize = 32;
pub const JSON_MAX_STRING_BYTES: usize = 256 * 1024;
pub const JSON_MAX_LIST_LENGTH: usize = 256;

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, WireError> {
    let json = serde_jcs::to_vec(value).map_err(malformed)?;
    if json.len() > FRAME_MAX_BYTES {
        return Err(limit("encoded frame exceeds 1 MiB"));
    }
    let mut frame = Vec::with_capacity(json.len() + 4);
    frame.extend_from_slice(&(json.len() as u32).to_be_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, WireError> {
    if frame.len() < 4 {
        return Err(malformed("frame is shorter than its length prefix"));
    }
    let declared = u32::from_be_bytes(frame[..4].try_into().expect("four-byte prefix")) as usize;
    if declared > FRAME_MAX_BYTES {
        return Err(limit("declared frame length exceeds 1 MiB"));
    }
    if frame.len() != declared + 4 {
        return Err(malformed("frame length prefix does not match input"));
    }
    let payload = &frame[4..];
    let value: serde_json::Value = serde_json::from_slice(payload).map_err(malformed)?;
    validate_json_shape(&value, 1)?;
    let canonical = serde_jcs::to_vec(&value).map_err(malformed)?;
    if canonical != payload {
        return Err(malformed("JSON payload is not RFC 8785 canonical"));
    }
    serde_json::from_value(value).map_err(|error| {
        if error.to_string().contains("unknown field") {
            WireError::new(WireErrorCode::UnknownField, error.to_string())
        } else {
            malformed(error)
        }
    })
}

fn validate_json_shape(value: &serde_json::Value, depth: usize) -> Result<(), WireError> {
    if depth > JSON_MAX_DEPTH {
        return Err(limit("JSON nesting depth exceeds 32"));
    }
    match value {
        serde_json::Value::String(value) if value.len() > JSON_MAX_STRING_BYTES => {
            Err(limit("JSON string exceeds 256 KiB"))
        }
        serde_json::Value::Array(values) => {
            if values.len() > JSON_MAX_LIST_LENGTH {
                return Err(limit("JSON list exceeds 256 elements"));
            }
            for value in values {
                validate_json_shape(value, depth + 1)?;
            }
            Ok(())
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                if key.len() > JSON_MAX_STRING_BYTES {
                    return Err(limit("JSON object key exceeds 256 KiB"));
                }
                validate_json_shape(value, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Base64UrlBytes(String);

impl Base64UrlBytes {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn parse(encoded: impl Into<String>) -> Result<Self, WireError> {
        let encoded = encoded.into();
        if encoded.contains('=') {
            return Err(malformed("base64url values must be unpadded"));
        }
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).map_err(malformed)?;
        if URL_SAFE_NO_PAD.encode(decoded) != encoded {
            return Err(malformed("base64url value is noncanonical"));
        }
        Ok(Self(encoded))
    }

    pub fn decode(&self) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(&self.0)
            .expect("validated base64url")
    }

    pub fn encoded(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Base64UrlBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

fn malformed(error: impl std::fmt::Display) -> WireError {
    WireError::new(WireErrorCode::MalformedFrame, error.to_string())
}

fn limit(message: impl Into<String>) -> WireError {
    WireError::new(WireErrorCode::LimitExceededFrame, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Example {
        a: String,
        z: u8,
    }

    #[test]
    fn canonical_frame_round_trips_and_noncanonical_input_fails() {
        let value = Example {
            a: "ok".into(),
            z: 7,
        };
        let frame = encode_frame(&value).unwrap();
        assert_eq!(decode_frame::<Example>(&frame).unwrap(), value);

        let json = br#"{"z":7,"a":"ok"}"#;
        let mut noncanonical = (json.len() as u32).to_be_bytes().to_vec();
        noncanonical.extend_from_slice(json);
        assert_eq!(
            decode_frame::<Example>(&noncanonical).unwrap_err().code,
            WireErrorCode::MalformedFrame
        );
    }
}
