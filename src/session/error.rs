use std::borrow::Cow;

/// Session errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failure in storage backend: {0}")]
    Store(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Encoding or decoding error: {0}")]
    Encoding(#[from] postcard::Error),

    #[error("Invalid state transition from {0} to {1}")]
    InvalidStateTransition(Cow<'static, str>, Cow<'static, str>),

    #[error("session has expired")]
    ExpiredSession,

    #[error("{0}")]
    Other(color_eyre::eyre::Report),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expired_session_error_message() {
        let error = Error::ExpiredSession;
        assert_eq!(format!("{}", error), "session has expired");
    }

    #[test]
    fn test_invalid_state_transition_error_message() {
        let error = Error::InvalidStateTransition("AwaitingConsent".into(), "Completed".into());
        assert_eq!(
            format!("{}", error),
            "Invalid state transition from AwaitingConsent to Completed"
        );
    }

    #[test]
    fn test_encoding_error_from_postcard() {
        let postcard_error = postcard::from_bytes::<String>(&[0xFF, 0xFE]).unwrap_err();
        let error: Error = Error::from(postcard_error);
        assert!(format!("{}", error).contains("Encoding or decoding error"));
    }

    #[test]
    fn test_store_error_wraps_source() {
        let source =
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");
        let error = Error::Store(Box::new(source));
        assert!(format!("{}", error).contains("Failure in storage backend"));
    }

    #[test]
    fn test_other_error_wraps_report() {
        let report = color_eyre::eyre::eyre!("something went wrong");
        let error = Error::Other(report);
        assert_eq!(format!("{}", error), "something went wrong");
    }
}
