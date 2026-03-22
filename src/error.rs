// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(feature = "std")]
use thiserror::Error;

/// Errors that can occur during KK operations.
#[derive(Debug)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum KkError {
    #[cfg_attr(feature = "std", error("entropy collection failed: {0}"))]
    EntropyFailure(String),

    #[cfg_attr(feature = "std", error("temporal commitment verification failed, entropic moment mismatch"))]
    CommitmentMismatch,

    #[cfg_attr(feature = "std", error("invalid packet: {0}"))]
    InvalidPacket(String),

    #[cfg_attr(feature = "std", error("empty input: nothing to encode"))]
    EmptyInput,

    #[cfg_attr(feature = "std", error(
        "epoch drift too large: claimed {claimed_nanos} ns, \
         drift {drift_nanos} ns exceeds max {max_nanos} ns"
    ))]
    EpochDrift {
        claimed_nanos: u128,
        drift_nanos: u128,
        max_nanos: u128,
    },

    #[cfg_attr(feature = "std", error("stale nonce: verifier nonce was already used or not recognized"))]
    StaleNonce,
}

#[cfg(not(feature = "std"))]
impl fmt::Display for KkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntropyFailure(s) => write!(f, "entropy collection failed: {s}"),
            Self::CommitmentMismatch => write!(f, "temporal commitment verification failed"),
            Self::InvalidPacket(s) => write!(f, "invalid packet: {s}"),
            Self::EmptyInput => write!(f, "empty input: nothing to encode"),
            Self::EpochDrift { claimed_nanos, drift_nanos, max_nanos } => {
                write!(f, "epoch drift too large: claimed {claimed_nanos} ns, drift {drift_nanos} ns exceeds max {max_nanos} ns")
            }
            Self::StaleNonce => write!(f, "stale nonce"),
        }
    }
}

pub type Result<T> = core::result::Result<T, KkError>;
