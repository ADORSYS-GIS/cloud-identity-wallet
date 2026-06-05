mod verifier;
pub mod wallet;

pub use verifier::{
    // Algorithm and proof types
    CoseAlgorithmIdentifier,
    // Core types
    CredentialFormatIdentifier,
    CryptosuiteIdentifier,
    ExtensionFormatCapability,
    JoseAlgorithmIdentifier,
    JweContentEncryptionAlgorithm,
    JweKeyManagementAlgorithm,
    // Format capabilities
    JwtVcJsonFormatCapability,
    LdpVcFormatCapability,
    MsoMdocFormatCapability,
    NonEmptyString,
    ProofTypeIdentifier,
    SdJwtVcFormatCapability,
    // Main struct
    VerifierMetadata,
    VpFormatCapability,
    VpFormatsSupported,
};
pub use wallet::WalletPresentationMetadata;
