use thiserror::Error;

/// Errors that can occur during KK operations.
#[derive(Debug, Error)]
pub enum KkError {
    #[error("entropy collection failed: {0}")]
    EntropyFailure(String),

    #[error("HKDF expand failed: key material too short")]
    KdfExpandFailure,

    #[error("temporal commitment verification failed  - entropic moment mismatch")]
    CommitmentMismatch,

    #[error("invalid packet: {0}")]
    InvalidPacket(String),

    #[error("empty input: nothing to encode")]
    EmptyInput,
}

pub type Result<T> = std::result::Result<T, KkError>;
