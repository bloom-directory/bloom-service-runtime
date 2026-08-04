//! Mechanical authenticated RPC wire primitives.
//!
//! This crate deliberately contains no wallet, key-registry, Petal, approval,
//! policy, custody, ceremony, credential, or signing domain contract.

#![forbid(unsafe_code)]

mod audit;
mod codec;
mod envelope;
mod error;
mod hello;
mod ids;

pub use audit::*;
pub use codec::*;
pub use envelope::*;
pub use error::*;
pub use hello::*;
pub use ids::*;
