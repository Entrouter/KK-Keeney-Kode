// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

use thiserror::Error;

/// Errors that can occur during KK operations.
#[derive(Debug, Error)]
pub enum KkError {
    #[error("entropy collection failed: {0}")]
    EntropyFailure(String),

    #[error("temporal commitment verification failed, entropic moment mismatch")]
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
