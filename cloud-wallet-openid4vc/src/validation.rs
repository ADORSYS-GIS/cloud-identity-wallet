/// Structural self-validation that a type can perform without external context.
pub trait Validatable {
    type Error;
    fn validate(&self) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use time::{Duration, OffsetDateTime};

    use crate::errors::Error;
    use crate::models::{
        Binding, Claims, Credential, CredentialId, CredentialMetadata, CredentialStatus,
        CredentialType,
    };
    use crate::schema::CredentialFormatIdentifier;
    use crate::validation::Validatable;

    fn sd_jwt_metadata() -> CredentialMetadata {
        CredentialMetadata {
            credential_configuration_id: "identity_credential".to_owned(),
            format: CredentialFormatIdentifier::DcSdJwt,
            raw_credential: "t".to_owned(),
        }
    }

    fn sd_jwt_credential() -> Result<Credential, Error> {
        Credential::new(
            "https://issuer.example.com",
            "user-1234",
            CredentialType::new("vct"),
            Claims::new(json!({})),
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(365)),
            None,
            Binding::none(),
            sd_jwt_metadata(),
        )
    }

    // Validate trait — impl lives in models.rs, tested here for coverage

    #[test]
    fn validate_trait_passes_for_valid_credential() -> Result<(), Box<dyn std::error::Error>> {
        let cred = sd_jwt_credential()?;
        assert!(cred.validate().is_ok());
        Ok(())
    }

    #[test]
    fn validate_trait_catches_blank_issuer() {
        let cred = Credential {
            id: CredentialId::new(),
            issuer: "  ".to_owned(),
            subject: "user-1234".to_owned(),
            credential_type: CredentialType::new("vct"),
            claims: Claims::new(json!({})),
            issued_at: OffsetDateTime::now_utc(),
            expires_at: None,
            status_reference: None,
            binding: Binding::none(),
            metadata: sd_jwt_metadata(),
            status: CredentialStatus::Active,
        };
        assert!(cred.validate().is_err());
    }
}
