/// Holder binding proof for SD-JWT VC presentations.
///
/// Contains the Key Binding JWT created by the holder to prove possession of the
/// credential's private key. The KB-JWT must be constructed by format-specific code
/// using the nonce and audience from the authorization request.
#[derive(Debug, Clone)]
pub struct SdJwtHolderBinding {
    pub key_binding_jwt: String,
}

impl SdJwtHolderBinding {
    pub fn new(key_binding_jwt: impl Into<String>) -> Self {
        Self {
            key_binding_jwt: key_binding_jwt.into(),
        }
    }
}

/// Holder binding proof for mdoc presentations.
///
/// Contains the device signature created by the holder. Per ISO 18013-5 Section B.2.5,
/// this is the DeviceAuth/DeviceSigned structure.
#[derive(Debug, Clone)]
pub struct MdocHolderBinding {
    pub device_signature: Vec<u8>,
}

impl MdocHolderBinding {
    pub fn new(device_signature: Vec<u8>) -> Self {
        Self { device_signature }
    }
}

/// Format-specific holder binding proof.
///
/// This enum allows presentation code to carry binding proofs without needing
/// to know the concrete format. Actual proof creation and embedding into presentation
/// strings should happen in format-specific modules (e.g., `formats::sd_jwt`).
#[derive(Debug, Clone)]
pub enum HolderBinding {
    SdJwt(SdJwtHolderBinding),
    Mdoc(MdocHolderBinding),
}