mod error;
mod scheme;

pub use error::{Error, Result};
pub use scheme::{
    CredentialOfferParams, HaipVciSource, HaipVciUri, HaipVpUri, extract_credential_offer_params,
    parse_credential_offer_uri, parse_haip_vci_uri, parse_haip_vp_uri, parse_vp_uri,
};
