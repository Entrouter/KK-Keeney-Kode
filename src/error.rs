use thiserror::Error;

/// Errors that can occur during KK operations.
#[derive(Debug, Error)]
pub enum KkError {
    #[error("entropy collection failed: {0}")]
    EntropyFailure(String),

    #[error("temporal commitment verification failed  - entropic moment mismatch")]
    CommitmentMismatch,

    #[error("invalid packet: {0}")]
    InvalidPacket(String),

    #[error("empty input: nothing to encode")]
    EmptyInput,

    #[error(
        "epoch drift too large: claimed {claimed_nanos} ns, \
         drift {drift_nanos} ns exceeds max {max_nanos} ns"
    )]
    EpochDrift {
        claimed_nanos: u128,
        drift_nanos: u128,
        max_nanos: u128,
    },

    #[error("stale nonce: verifier nonce was already used or not recognized")]
    StaleNonce,
}

pub type Result<T> = std::result::Result<T, KkError>;
