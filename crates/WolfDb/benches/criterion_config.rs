//! Configuration for `WolfDb` benchmarks.

use criterion::{Criterion, PlottingBackend};
use std::time::Duration;

/// Returns the standard `Criterion` configuration used for `WolfDb` benchmarks.
#[must_use]
pub fn wolf_db_bench_config() -> Criterion {
    Criterion::default()
        .sample_size(500)
        .warm_up_time(Duration::from_secs(5))
        .plotting_backend(PlottingBackend::Gnuplot)
}
