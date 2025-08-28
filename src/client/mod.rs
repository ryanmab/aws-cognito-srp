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
pub trait Credentials: private::Sealed + Send + Sync {}

/// The parameters required to initiate an authentication flow with AWS Cognito, when using the
/// `USER_SRP_AUTH` flow type.
///
/// For the full request structure see documentation: [InitiateAuth](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html)
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct AuthParameters {
    /// The **public** `A` for the client.
    pub a: String,

    /// The username of the user - this is the one provided during
    /// instantiation of the SRP client.
    ///
    /// This will only be returned when using [User] credentials.
    pub username: Option<String>,

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
#[must_use]
pub struct VerificationParameters {
    /// The secret block provided by AWS Cognito at the start of the authentication flow.
    pub password_claim_secret_block: String,

    /// The signature of the password claim generated during verification.
    pub password_claim_signature: String,

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
    /// protocol with a new set of credentials of the same type, and return
    /// the previous credentials.
    ///
    /// **Note:** This _will not_ update the client ID, client secret, or the pre-generated
    /// `a` value.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use aws_cognito_srp::{PasswordVerifierParameters, SrpClient, UntrackedDevice};
    ///
    /// let mut client = SrpClient::new(
    ///     UntrackedDevice::new("mock-pool-id", "mock-device-group-key", "mock-device-key"),
    ///     "mock-client-id",
    ///     None,
    /// );
    ///
    /// let PasswordVerifierParameters { .. } = client.get_password_verifier();
    ///
    /// let untracked_device = client.replace_credentials(
    ///     UntrackedDevice::new("mock-new-pool-id", "mock-new-device-group-key", "mock-new-device-key")
    /// );
    ///
    /// # assert!(matches!(untracked_device, UntrackedDevice { .. }));
    /// ```
    pub fn replace_credentials(&mut self, credentials: C) -> C {
        mem::replace(&mut self.credentials, credentials)
    }

    /// Convert the client into a new client which handles a different type of credentials, preserving
    /// the existing client ID and client secret in the process.
    ///
    /// **Note:** This _will_ update the pre-generated `a` value, meaning the client will not be
    /// able to continue an existing authentication flow (as the `a` value is used in the calculation
    /// of parameters in the SRP flow).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use aws_cognito_srp::{PasswordVerifierParameters, SrpClient, TrackedDevice, UntrackedDevice};
    ///
    /// let client = SrpClient::new(
    ///     UntrackedDevice::new("mock-pool-id", "mock-device-group-key", "mock-device-key"),
    ///     "mock-client-id",
    ///     None,
    /// );
    ///
    /// let PasswordVerifierParameters { password, .. } = client.get_password_verifier();
    ///
    /// let client = client.into(
    ///     TrackedDevice::new(
    ///         "mock-pool-id",
    ///         "mock-device-group-key",
    ///         "mock-device-key",
    ///         &password
    ///    )
    /// );
    ///
    /// # assert!(matches!(client, SrpClient::<TrackedDevice> { .. }));
    /// ```
    pub fn into<T: Credentials>(self, credentials: T) -> SrpClient<T> {
        SrpClient::new(credentials, &self.client_id, self.client_secret.as_deref())
    }

    /// Take the credentials which were used by the SRP client.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use aws_cognito_srp::{PasswordVerifierParameters, SrpClient, UntrackedDevice};
    ///
    /// let client = SrpClient::new(
    ///     UntrackedDevice::new("mock-pool-id", "mock-device-group-key", "mock-device-key"),
    ///     "mock-client-id",
    ///     None,
    /// );
    ///
    /// let PasswordVerifierParameters { .. } = client.get_password_verifier();
    ///
    /// let untracked_device = client.take_credentials();
    ///
    /// # assert!(matches!(untracked_device, UntrackedDevice { .. }));
    /// ```
    pub fn take_credentials(self) -> C {
        self.credentials
    }

    /// Get the secret hash to be used on login and challenge requests to AWS Cognito.
    ///
    /// The User ID is typically the username (and likely the email address) of the user, but
    /// can depend on the configuration of the AWS Cognito User Pool, and whether the secret is being
    /// used for the `InitiateAuth` or `RespondToAuthChallenge` request.
    ///
    /// Calculation is: `BASE64(HMAC_SHA256(<client secret>, <user id> + <client id>))`
    pub(crate) fn get_secret_hash_for_user_id(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Option<String> {
        self.client_secret.as_ref().and_then(|secret| {
            let mut hmac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
            hmac.update(user_id.as_bytes());
            hmac.update(client_id.as_bytes());

            let hash = BASE64.encode(hmac.finalize().into_bytes());

            info!(hash = hash.as_str(); "Generated client secret hash for user");

            Some(hash)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SrpClient;
    use crate::{PasswordVerifierParameters, UntrackedDevice};

    #[test]
    pub fn test_taking_and_replacing_credentials() {
        let untracked_device = UntrackedDevice::new(
            "eu_west_1-abc123",
            "mock-device-group-key",
            "mock-device-key",
        );

        let client = SrpClient::new(
            untracked_device,
            "some-client-id",
            Some("some-client-secret"),
        );

        // Generate the password verifier for the confirm device flow
        let password_verifier = client.get_password_verifier();
        assert!(matches!(
            password_verifier,
            PasswordVerifierParameters { .. }
        ));

        // Complete the confirm device flow, and take the (untracked device) credentials back
        let taken_credentials = client.take_credentials();
        assert!(matches!(taken_credentials, UntrackedDevice { .. }));

        // Convert the untracked device into a tracked device (as we have now confirmed the device now),
        // and create a new client with the tracked device credentials
        let tracked_device = taken_credentials.into_tracked(&password_verifier.password);
        let _ = SrpClient::new(tracked_device, "some-client-id", Some("some-client-secret"));
    }
}
