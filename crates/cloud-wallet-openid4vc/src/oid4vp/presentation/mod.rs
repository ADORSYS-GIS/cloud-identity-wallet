mod builder;
mod error;
pub mod formats;

pub use builder::{PresentationBuilder, SelectedCredential};
pub use error::{PresentationBuilderError, ProofError};

use crate::oid4vp::authorization::Presentation;

/// Creates a verifiable presentation for a selected credential.
///
/// Each credential format (SD-JWT VC, mdoc, etc.) provides its own
/// implementation that assembles the format-specific presentation and includes
/// holder-binding proof material when required by the presentation request.
pub trait PresentationFactory: Send + Sync + 'static {
    /// Creates the presentation.
    ///
    /// Implementations consume `self` because presentation construction is normally
    /// a one-shot operation over nonce-bound request data.
    fn create_presentation(self) -> Result<Presentation, ProofError>;
}
