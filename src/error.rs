use thiserror::Error;

/// An error occurred while generating a parameters for the Secure Remote Password (SRP)
/// protocol.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SrpError {
    /// An argument which was provided to the client was invalid.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// The HMAC algorithm failed to generate a hash as the digest length was invalid.
    #[error("Cryptography error: {0}")]
    CryptographyError(#[from] digest::InvalidLength),
}
