// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! Pre-generated entropy pool for high-throughput encode paths.
//!
//! Every `encode()` call invokes `entropy::gather()`, which includes a
//! 64-iteration thread-jitter loop (~50-200 μs).  For bulk encryption
//! this overhead is unnecessary: we can pre-generate snapshots in a
//! background thread and hand them out instantly.
//!
//! # Usage
//! ```no_run
//! use kk_crypto::{EntropyPool, encode_pooled, encode_aead_pooled};
//!
//! let pool = EntropyPool::new(64).unwrap();
//! let packet = encode_pooled(b"secret", b"hello", &pool).unwrap();
//! ```

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crate::entropy::{self, EntropySnapshot};
use crate::error::Result;

/// A pre-warmed pool of [`EntropySnapshot`] values for low-latency draws.
///
/// The pool spawns a background thread that continuously generates snapshots
/// via `entropy::gather()` and refills the pool whenever it falls below a
/// watermark (50% of capacity).  Draws are nearly instant (mutex lock + pop).
///
/// If the pool is temporarily exhausted, `draw()` falls back to a synchronous
/// `entropy::gather()` call so correctness is never compromised.
pub struct EntropyPool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    state: Mutex<PoolState>,
    /// Signaled when the pool drops below the watermark.
    need_refill: Condvar,
    /// Signaled when new snapshots are added.
    snapshot_added: Condvar,
    capacity: usize,
    watermark: usize,
}

struct PoolState {
    buf: VecDeque<EntropySnapshot>,
    shutdown: bool,
}

impl EntropyPool {
    /// Create a new pool that holds up to `capacity` pre-generated snapshots.
    ///
    /// Blocks until at least 8 snapshots (or `capacity`, whichever is smaller)
    /// are ready.  The background refill thread starts immediately.
    ///
    /// # Panics
    /// If `capacity` is 0.
    pub fn new(capacity: usize) -> Result<Self> {
        assert!(capacity > 0, "EntropyPool capacity must be > 0");
        let capacity = capacity.clamp(8, 1024);
        let watermark = capacity / 2;
        let prewarm = capacity.min(8);

        let inner = Arc::new(PoolInner {
            state: Mutex::new(PoolState {
                buf: VecDeque::with_capacity(capacity),
                shutdown: false,
            }),
            need_refill: Condvar::new(),
            snapshot_added: Condvar::new(),
            capacity,
            watermark,
        });

        // Spawn background refill thread
        let worker = Arc::clone(&inner);
        thread::spawn(move || refill_loop(worker));

        // Signal the worker to start filling
        inner.need_refill.notify_one();

        // Block until pre-warmed
        {
            let mut state = inner.state.lock().unwrap();
            while state.buf.len() < prewarm {
                state = inner.snapshot_added.wait(state).unwrap();
            }
        }

        Ok(Self { inner })
    }

    /// Draw a single [`EntropySnapshot`] from the pool.
    ///
    /// If the pool has snapshots ready, this is a fast mutex-pop (~ns).
    /// If the pool is exhausted, falls back to synchronous `entropy::gather()`.
    pub fn draw(&self) -> Result<EntropySnapshot> {
        let mut state = self.inner.state.lock().unwrap();
        if let Some(snap) = state.buf.pop_front() {
            let below_watermark = state.buf.len() < self.inner.watermark;
            drop(state);
            if below_watermark {
                self.inner.need_refill.notify_one();
            }
            Ok(snap)
        } else {
            drop(state);
            // Pool exhausted - fall back to synchronous gather
            entropy::gather()
        }
    }

    /// Number of snapshots currently available (approximate).
    pub fn len(&self) -> usize {
        self.inner.state.lock().unwrap().buf.len()
    }

    /// Returns `true` if the pool currently has no snapshots.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for EntropyPool {
    fn drop(&mut self) {
        let mut state = self.inner.state.lock().unwrap();
        state.shutdown = true;
        drop(state);
        self.inner.need_refill.notify_one();
    }
}

/// Background loop: generate snapshots until the pool is full, then park
/// until woken by the watermark signal.
fn refill_loop(inner: Arc<PoolInner>) {
    loop {
        let mut state = inner.state.lock().unwrap();

        // Wait until we need to refill or are told to shut down
        while !state.shutdown && state.buf.len() >= inner.capacity {
            state = inner.need_refill.wait(state).unwrap();
        }

        if state.shutdown {
            return;
        }

        let slots = inner.capacity - state.buf.len();
        drop(state);

        // Generate snapshots outside the lock
        for _ in 0..slots {
            // Check shutdown between generations
            {
                let st = inner.state.lock().unwrap();
                if st.shutdown {
                    return;
                }
            }

            if let Ok(snap) = entropy::gather() {
                let mut state = inner.state.lock().unwrap();
                if state.buf.len() < inner.capacity {
                    state.buf.push_back(snap);
                    drop(state);
                    inner.snapshot_added.notify_one();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_creates_and_prewarms() {
        let pool = EntropyPool::new(16).unwrap();
        assert!(pool.len() >= 8, "pool should pre-warm at least 8 snapshots");
    }

    #[test]
    fn draw_returns_valid_snapshot() {
        let pool = EntropyPool::new(16).unwrap();
        let snap = pool.draw().unwrap();
        assert_ne!(snap.bytes, [0u8; 32], "snapshot bytes must be non-zero");
        assert_ne!(snap.timestamp_nanos, 0, "timestamp must be non-zero");
    }

    #[test]
    fn successive_draws_differ() {
        let pool = EntropyPool::new(16).unwrap();
        let s1 = pool.draw().unwrap();
        let s2 = pool.draw().unwrap();
        assert_ne!(s1.bytes, s2.bytes, "two draws must produce different snapshots");
    }

    #[test]
    fn draw_under_exhaustion_still_works() {
        // Create smallest pool, drain it, then draw again (should fallback)
        let pool = EntropyPool::new(8).unwrap();
        // Drain all pre-warmed snapshots
        for _ in 0..8 {
            let _ = pool.draw().unwrap();
        }
        // This should either get a refilled one or fall back to gather()
        let snap = pool.draw().unwrap();
        assert_ne!(snap.bytes, [0u8; 32]);
    }

    #[test]
    fn pool_refills_after_drain() {
        let pool = EntropyPool::new(16).unwrap();
        // Drain
        for _ in 0..8 {
            let _ = pool.draw().unwrap();
        }
        // Give the background thread a moment to refill
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(pool.len() > 0, "pool should refill after draws");
    }
}
