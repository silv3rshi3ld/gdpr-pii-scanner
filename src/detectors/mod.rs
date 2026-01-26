pub mod be; // Belgium
pub mod de; // Germany
pub mod es; // Spain
pub mod eu; // Pan-European
pub mod financial; // Universal financial
pub mod fr; // France
pub mod gb; // United Kingdom
pub mod it; // Italy
/// PII Detectors for various countries and data types
pub mod nl; // Netherlands
pub mod personal; // Universal personal
pub mod security; // Universal security

// Re-export common detector types
pub use crate::core::Detector;
