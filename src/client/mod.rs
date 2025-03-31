use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, Mac};
use log::info;
use sha2::Sha256;
use std::mem;

pub use device::TrackedDevice;
pub use device::UntrackedDevice;
pub use user::User;

mod device;
mod helper;
mod user;

type HmacSha256 = Hmac<Sha256>;

mod private {
    pub trait Sealed {}
}

/// The credentials required to authenticate with AWS Cognito using the Secure Remote
/// Password (SRP).
///
/// These come in three forms:
/// 1. [`User`] - For authenticating via SRP with a user.
/// 2. [`TrackedDevice`] - For authenticating via SRP with a remembered device.
/// 3. [`UntrackedDevice`] - For generating a password verifier for a new device during confirmation.
pub trait Credentials: private::Sealed {}

/// The parameters required to initiate an authentication flow with AWS Cognito, when using the
/// `USER_SRP_AUTH` flow type.
///
/// For the full request structure see documentation: [InitiateAuth](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html)
#[derive(Debug, Eq, PartialEq)]
pub struct AuthParameters {
    /// The **public** `A` for the client.
    pub a: String,

    /// The username of the user - this is the one provided during
    /// instantiation of the SRP client.
    ///
    /// This will only be returned when using [User] credentials.
    pub username: Option<String>,

    /// The hash of the client secret provided during instantiation of the SRP client (if
    /// one was provided).
    pub secret_hash: Option<String>,

    /// The device key of the tracked device.
    ///
    /// This will only be returned when using [`TrackedDevice`] credentials.
    pub device_key: Option<String>,
}

/// The parameters required to respond to the `PASSWORD_VERIFIER` (if authenticating as a User) and `DEVICE_PASSWORD_VERIFIER`
/// (if authenticating using a Device) challenges.
///
/// For the full request structure see documentation: [RespondToAuthChallenge](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html)
#[derive(Debug, Eq, PartialEq)]
pub struct VerificationParameters {
    /// The secret block provided by AWS Cognito at the start of the authentication flow.
    pub password_claim_secret_block: String,

    /// The signature of the password claim generated during verification.
    pub password_claim_signature: String,

    /// The hash of the client secret provided during instantiation
    /// of the SRP client (if one was provided).
    ///
    /// As the hash is computed using the username, this will only be returned when
    /// using [User] credentials.
    pub secret_hash: Option<String>,

    /// The timestamp of the verification.
    pub timestamp: String,
}

/// The parameters required to generate a password verifier when confirming a new device in AWS Cognito.
///
/// For the full request structure see documentation: [ConfirmDevice](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmDevice.html)
#[derive(Debug, Eq, PartialEq)]
pub struct PasswordVerifierParameters {
    /// The verifier which can be used by the server to verify the provided password.
    pub verifier: String,

    /// The salt used to generate the verifier.
    pub salt: String,

    /// The random password which can be used by the client to authenticate against the
    /// verifier.
    pub password: String,
}

/// The client for interacting with parameters required for the Secure Remote Password (SRP) protocol.
///
/// This client comes in three forms:
/// 1. [`User`] - For authenticating via SRP with a user.
/// 2. [`TrackedDevice`] - For authenticating via SRP with a remembered device.
/// 3. [`UntrackedDevice`] - For generating a password verifier for a new device during confirmation.
#[derive(Debug)]
pub struct SrpClient<C: Credentials> {
    a: Vec<u8>,
    credentials: C,
    client_id: String,
    client_secret: Option<String>,
}

impl<C: Credentials> SrpClient<C> {
    /// Create a new SRP client.
    ///
    /// If the client secret is not provided, the client will not generate a secret hash
    /// for use in the authentication flow.
    #[must_use]
    pub fn new(credentials: C, client_id: &str, client_secret: Option<&str>) -> Self {
        Self {
            a: helper::generate_a(),
            credentials,
            client_id: client_id.into(),
            client_secret: client_secret.map(std::convert::Into::into),
        }
    }

    /// Replace the credentials used internally by the client for the SRP
    /// protocol, and return the previous credentials.
    ///
    /// **Note:** This will not update the client ID, client secret, or the pre-generated
    /// `a` value.
    pub fn replace_credentials(&mut self, credentials: C) -> impl Credentials {
        mem::replace(&mut self.credentials, credentials)
    }

    /// Take the credentials which were used by the SRP client.
    pub fn take_credentials(self) -> C {
        self.credentials
    }

    /// Get the secret hash to be used on login and challenge requests to AWS Cognito.
    ///
    /// Calculation is: `BASE64(HMAC_SHA256(<client secret>, <username> + <client id>))`
    fn get_secret_hash(&self, username: &str, client_id: &str) -> Option<String> {
        self.client_secret.as_ref().and_then(|secret| {
            let mut hmac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
            hmac.update(username.as_bytes());
            hmac.update(client_id.as_bytes());

            let hash = BASE64.encode(hmac.finalize().into_bytes());

            info!(hash = hash.as_str(); "Generated client secret hash for user");

            Some(hash)
        })
    }
}
