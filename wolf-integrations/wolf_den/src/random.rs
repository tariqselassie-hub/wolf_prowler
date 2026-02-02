//! Random number generation for Wolf Den

use rand::rngs::OsRng;
use rand::RngCore;

/// Get a cryptographically secure random number generator
#[must_use]
pub fn global_rng() -> impl RngCore + Send + Sync {
    OsRng
}
