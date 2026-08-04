use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

use crate::{WireError as ProtocolError, WireErrorCode as ProtocolErrorCode};

const TOKEN_MAX_BYTES: usize = 64;

/// A short, lowercase protocol identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Token(String);

impl Token {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        if valid_token(&value) {
            Ok(Self(value))
        } else {
            Err(ProtocolError::fatal(
                ProtocolErrorCode::MalformedFrame,
                "token must be a 1-64 byte lowercase ASCII protocol identifier",
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Token {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Token {
    type Err = ProtocolError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

fn valid_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= TOKEN_MAX_BYTES
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b'/')
        })
}

macro_rules! fixed_lower_hex {
    ($name:ident, $bytes:expr, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub const HEX_LENGTH: usize = $bytes * 2;

            pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
                let value = value.into();
                if value.len() == Self::HEX_LENGTH
                    && value
                        .as_bytes()
                        .iter()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                {
                    Ok(Self(value))
                } else {
                    Err(ProtocolError::fatal(
                        ProtocolErrorCode::MalformedFrame,
                        concat!($description, " must be fixed-length lowercase hexadecimal"),
                    ))
                }
            }

            pub fn from_bytes(bytes: [u8; $bytes]) -> Self {
                Self(hex::encode(bytes))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn to_bytes(&self) -> [u8; $bytes] {
                let decoded = hex::decode(&self.0).expect("validated fixed hexadecimal");
                decoded.try_into().expect("validated fixed length")
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ProtocolError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

fixed_lower_hex!(Digest32, 32, "SHA-256 digest");
fixed_lower_hex!(OperationId, 32, "operation ID");
fixed_lower_hex!(BootEpoch, 16, "boot epoch");
fixed_lower_hex!(RequestNonce, 16, "request nonce");

/// Canonical unsigned 64-bit decimal string.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DecimalU64(String);

impl DecimalU64 {
    pub fn new(value: u64) -> Self {
        Self(value.to_string())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        let parsed = parse_canonical_decimal(&value).and_then(|number| u64::try_from(number).ok());
        parsed.map(Self::new).ok_or_else(|| {
            ProtocolError::fatal(
                ProtocolErrorCode::MalformedFrame,
                "value must be a canonical unsigned 64-bit decimal string",
            )
        })
    }

    pub fn get(&self) -> u64 {
        self.0.parse().expect("validated u64")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DecimalU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Canonical unsigned 256-bit decimal string.
///
/// Arithmetic is intentionally implemented in the owning Broker package; W1
/// validates the closed wire representation without introducing key or policy
/// behavior into this shared crate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DecimalU256(String);

impl DecimalU256 {
    pub fn parse(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        if value.len() <= 78
            && is_canonical_decimal(&value)
            && decimal_leq(
                &value,
                "115792089237316195423570985008687907853269984665640564039457584007913129639935",
            )
        {
            Ok(Self(value))
        } else {
            Err(ProtocolError::fatal(
                ProtocolErrorCode::MalformedFrame,
                "value must be a canonical unsigned 256-bit decimal string",
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DecimalU256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

fn parse_canonical_decimal(value: &str) -> Option<u128> {
    if !is_canonical_decimal(value) {
        return None;
    }
    value.parse().ok()
}

fn is_canonical_decimal(value: &str) -> bool {
    !(value.is_empty() || value.len() > 1 && value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn decimal_leq(left: &str, right: &str) -> bool {
    left.len() < right.len() || (left.len() == right.len() && left <= right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_closed_and_lowercase() {
        assert!(Token::new("aws-kms.eu_west-2").is_ok());
        assert!(Token::new("bloom.sign-request/1").is_ok());
        for invalid in ["", "Upper", ".leading", "a b"] {
            assert!(Token::new(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn decimal_forms_are_canonical_and_bounded() {
        assert_eq!(
            DecimalU64::parse("18446744073709551615").unwrap().get(),
            u64::MAX
        );
        assert!(DecimalU64::parse("00").is_err());
        assert!(DecimalU64::parse("+1").is_err());
        assert!(DecimalU64::parse("18446744073709551616").is_err());
        assert!(
            DecimalU256::parse(
                "115792089237316195423570985008687907853269984665640564039457584007913129639935"
            )
            .is_ok()
        );
        assert!(
            DecimalU256::parse(
                "115792089237316195423570985008687907853269984665640564039457584007913129639936"
            )
            .is_err()
        );
    }
}
