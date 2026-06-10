use crate::oid4vp::{authorization::Presentation, presentation::error::HolderBindingProofError};

/// Creates a holder-binding proof for verifiable presentation.
pub trait HolderBindingProof: Send + Sync + 'static {
    /// Creates a holder-binding proof presentation.
    fn create_proof(&self) -> Result<Presentation, HolderBindingProofError>;
}
