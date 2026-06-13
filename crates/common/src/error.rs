// crates/common/src/error.rs

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("Package not found: {0}")]
    NotFound(String),

    #[error("Package is revoked: {reason}")]
    Revoked { reason: String },

    #[error("Signature verification failed for {pubkey}")]
    InvalidSignature { pubkey: String },

    #[error("Consensus failed: only {got}/{required} validators approved")]
    ConsensusFailed { got: usize, required: usize },

    #[error("Validator {id} is not in the active set")]
    UnknownValidator { id: String },

    #[error("Chain node unreachable: {url}")]
    NodeUnreachable { url: String },

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("IPFS error: {0}")]
    IpfsError(String),

    #[error("Validation failed: {reason}")]
    ValidationFailed { reason: String },

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RegistryError>;
