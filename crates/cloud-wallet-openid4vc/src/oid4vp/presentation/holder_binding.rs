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

#[derive(Debug, Clone)]
pub struct MdocHolderBinding {
    pub device_signature: Vec<u8>,
}

impl MdocHolderBinding {
    pub fn new(device_signature: Vec<u8>) -> Self {
        Self { device_signature }
    }
}

#[derive(Debug, Clone)]
pub enum HolderBinding {
    SdJwt(SdJwtHolderBinding),
    Mdoc(MdocHolderBinding),
}
