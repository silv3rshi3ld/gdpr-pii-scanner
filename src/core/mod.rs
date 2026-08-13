pub mod context;
pub mod detector;
pub mod plugin;
/// Core types and traits for PII-Radar
pub mod types;

pub use context::*;
pub use detector::{DetectionOutcome, Detector, DetectorRegistry};
#[allow(deprecated)]
#[deprecated(
    since = "0.6.0",
    note = "use the canonical crate-root plugin exports; legacy names will be removed in 0.7"
)]
pub use plugin::*;
pub use types::*;
