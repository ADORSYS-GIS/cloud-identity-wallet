use std::fmt;

use crate::error::{Error, ErrorKind};

pub(crate) fn key_gen_error(key: &str) -> Error {
    Error::message(
        ErrorKind::KeyGeneration,
        format!("Failed to generate {key} key"),
    )
}

pub(crate) fn error_msg<M>(kind: ErrorKind, msg: M) -> Error
where
    M: fmt::Display + fmt::Debug + Send + Sync + 'static,
{
    Error::message(kind, msg)
}

pub(crate) fn parse_error<M>(msg: M) -> Error
where
    M: fmt::Display + fmt::Debug + Send + Sync + 'static,
{
    error_msg(ErrorKind::KeyParsing, msg)
}

pub(crate) fn serialize_error<M>(msg: M) -> Error
where
    M: fmt::Display + fmt::Debug + Send + Sync + 'static,
{
    error_msg(ErrorKind::Serialization, msg)
}

impl From<pkcs8::Error> for Error {
    fn from(err: pkcs8::Error) -> Self {
        parse_error(err)
    }
}

impl From<pkcs8::spki::Error> for Error {
    fn from(err: pkcs8::spki::Error) -> Self {
        parse_error(err)
    }
}

impl From<pkcs8::der::Error> for Error {
    fn from(err: pkcs8::der::Error) -> Self {
        parse_error(err)
    }
}
