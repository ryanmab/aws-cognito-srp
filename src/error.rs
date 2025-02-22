use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum SrpError {
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Cryptography error: {0}")]
    CryptographyError(#[from] digest::InvalidLength),
}
