mod builder;
mod error;
mod proof;

pub use builder::{PresentationBuilder, SelectedCredential};
pub use error::{HolderBindingProofError, PresentationBuilderError};
pub use proof::HolderBindingProof;

pub use crate::oid4vp::authorization::VpTokenError;
