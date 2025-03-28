use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use digest::{Digest, Mac, Output};
use log::info;
use sha2::Sha256;

use crate::client::helper::{
    compute_k, compute_pub_a, compute_pub_b, compute_s, compute_u, compute_x,
    generate_key_derive_data, get_timestamp, left_pad, left_pad_to_even_length,
};
use crate::client::{private, AuthParameters, HmacSha256, VerificationParameters};
use crate::{Credentials, SrpClient, SrpError};

/// A **user** stored in the AWS Cognito user pool.
///
/// This user _does not_ have a tracked device (or device key) so may be
/// subject to additional challenges during authentication flows (depending on
/// user pool configuration).
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct User {
    /// The ID of the AWS Cognito User Pool the user is registered with.
    ///
    /// The format enforced by AWS Cognito is: `<region>_<pool id>`.
    ///
    /// For example: `us-east-1_SqmNeowUdp`.
    pool_id: String,
    username: String,
    password: String,
}
impl private::Sealed for User {}
impl Credentials for User {}

impl User {
    /// Create a new user which is already registered with the AWS Cognito user pool.
    #[must_use]
    pub fn new<'a>(pool_id: &'a str, username: &'a str, password: &'a str) -> Self {
        Self {
            pool_id: pool_id.into(),
            username: username.into(),
            password: password.into(),
        }
    }
}

impl SrpClient<User> {
    /// Generate the authentication parameters for the initial `InitiateAuth` request.
    ///
    /// This begins the SRP authentication flow with AWS Cognito, and exchanges the various
    /// initial public parameters which can then be used to validate the user's password.
    #[must_use]
    pub fn get_auth_parameters(&self) -> AuthParameters {
        let User { username, .. } = &self.credentials;

        info!(username = username.as_str(); "Generating auth parameters for user");

        AuthParameters {
            username: Some(username.into()),
            device_key: None,
            a: hex::encode(compute_pub_a(&self.a)),
            secret_hash: self.get_secret_hash(username, &self.client_id),
        }
    }

    /// Generate the challenge response parameters for the `PASSWORD_VERIFIER` challenge issued by
    /// AWS Cognito in response to the `InitiateAuth` request.
    ///
    /// These parameters verify to Cognito that the password known by the client is correct.
    ///
    /// ## Errors
    ///
    /// Returns an error if any of the input values are invalid. For example, if the `b` or `salt`
    /// values are not valid hex strings.
    pub fn verify(
        &self,
        secret_block: &str,
        user_id: &str,
        salt: &str,
        b: &str,
    ) -> Result<VerificationParameters, SrpError> {
        let pool_name = self.credentials.pool_id.split('_').nth(1).ok_or_else(|| {
            SrpError::InvalidArgument(
                "Invalid pool_id must be in the form `<region>_<pool id>`".into(),
            )
        })?;

        let key = self.get_password_authentication_key(
            user_id,
            &hex::decode(left_pad_to_even_length(b, '0')).map_err(|err| {
                SrpError::InvalidArgument(format!("Invalid SRP_B. Received '{err}'"))
            })?,
            &hex::decode(left_pad_to_even_length(salt, '0')).map_err(|err| {
                SrpError::InvalidArgument(format!("Invalid salt. Received '{err}'"))
            })?,
        )?;

        let timestamp = get_timestamp();

        let mut msg: Vec<u8> = vec![];
        msg.extend_from_slice(pool_name.as_bytes());
        msg.extend_from_slice(user_id.as_bytes());
        msg.extend_from_slice(&BASE64.decode(secret_block).map_err(|err| {
            SrpError::InvalidArgument(format!("Invalid base64 secret block. Received '{err}'"))
        })?);
        msg.extend_from_slice(timestamp.as_bytes());

        let mut h256mac = HmacSha256::new_from_slice(&key)?;
        h256mac.update(&msg);
        let signature = BASE64.encode(h256mac.finalize().into_bytes());

        Ok(VerificationParameters {
            timestamp,
            password_claim_secret_block: secret_block.into(),
            password_claim_signature: signature,
            secret_hash: self.get_secret_hash(user_id, &self.client_id),
        })
    }

    /// Generate the password authentication key for the user.
    ///
    /// This key is then used in the final signature for the SRP verification flow.
    fn get_password_authentication_key(
        &self,
        user_id: &str,
        b: &[u8],
        salt: &[u8],
    ) -> Result<Vec<u8>, SrpError> {
        let identity = self.compute_identity::<Sha256>(user_id)?;

        let a_pub = compute_pub_a(&self.a);
        let b_pub = compute_pub_b(b);

        let u = compute_u::<Sha256>(&a_pub, &b_pub);
        let x = compute_x::<Sha256>(identity.as_slice(), salt);
        let k = compute_k::<Sha256>();

        // Compute the shared secret
        let s = compute_s(&self.a, &u, &x, k, b);

        // Hash-based Key Derivation Function
        let mut hkdf = HmacSha256::new_from_slice(&left_pad(&u.to_bytes_be(), 0))?;
        hkdf.update(&left_pad(&s.to_bytes_be().1, 0));
        let prk = hkdf.finalize().into_bytes();

        hkdf = HmacSha256::new_from_slice(&prk)?;
        hkdf.update(&generate_key_derive_data());

        let ak = &hkdf.finalize().into_bytes()[..16];

        Ok(ak.to_vec())
    }

    /// Compute identity (`I`) variable in the SRP protocol.
    ///
    /// For AWS Cognito this is the SHA256 of `<pool name><username>:<password>`.
    fn compute_identity<D: Digest>(&self, user_id: &str) -> Result<Output<D>, SrpError> {
        let User {
            pool_id, password, ..
        } = &self.credentials;

        let mut d = D::new();

        d.update(pool_id.split('_').nth(1).ok_or_else(|| {
            SrpError::InvalidArgument(
                "Invalid pool_id must be in the form `<region>_<pool id>`".into(),
            )
        })?);
        d.update(user_id.as_bytes());
        d.update(b":");
        d.update(password.as_bytes());
        Ok(d.finalize())
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::{SrpClient, User, VerificationParameters};

    const MOCK_A: &str = "e13e5e4bdcb2670718d3141be1c00299211c244b6e0ec0c404e5c6c126fcefcbf3f5f165822a56e25f9906be1fba382a48eeb6b3915f12c91934e6ac4f18f0e2d20fdb77cba8ca0c5bbfda16c05686a6820ade1a5eeb1dfc551b96bed06ed8b14b218127d4d84f32ee9aa6fc32d100240a914d8708dd5bb68827a1a4be3dc4a129e1c08a4787739f6041dd966d1996c9ced9f72960f3e3c0e802d04beaa2e71c9af5a7d7dd1f3c695a80db20eb069f5bda0356ba9851a41a5c55ed68636e0aedacb1f7d370f25ef9186f5112866ad71aa825fda6991ac8d262b7a2765af07b65735cdca7e8d71f3b7d5c5d97297561e157ccdc40e034ecc71a38e534b1a2456962b5218bd533774462220d18c2ce8fb36e40fc61710f202df65d378eed2a8d811bcce5b2ee5013e3e8a3b3fde40dfb90f4d1e9eac28b3f396edeb119c98dae8d65aa17287767c4a38113b698312ff5ac351d10a5171e01ddf8fd1245c78716cf1610a60d0d82f94def26f646f91a347353276289af65f6c0bb6f95a84fa47c37";

    const MOCK_B: &str = "36ef01c6dde9fe503da333b1acc758ba";

    const MOCK_SALT: &str = "36ef01c6dde9fe503da333b1acc758ba";

    const MOCK_SECRET_BLOCK: &str = "9ae77ec7154c14dcc487b47707fee4b4920cb96d8a8c045e4c8df879a7b375524aa736acdec6c9ad4ea606774d00621b";

    struct MockRng {
        data: [u8; 8],
        index: usize,
    }
    impl RngCore for MockRng {
        fn next_u32(&mut self) -> u32 {
            unimplemented!()
        }

        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest.iter_mut() {
                *byte = self.data[self.index];
                self.index = (self.index + 1) % self.data.len();
            }
        }
    }

    impl Default for MockRng {
        fn default() -> Self {
            MockRng {
                data: [0, 1, 2, 3, 4, 5, 6, 7],
                index: 0,
            }
        }
    }

    #[test]
    fn test_auth_parameters_generates_successfully() {
        let client = SrpClient::<User>::new(
            User::new("us-west-2_abc", "test", "password"),
            "client_id",
            None,
        );

        assert_eq!(
            client.get_auth_parameters(),
            crate::client::AuthParameters {
                username: Some("test".to_string()),
                secret_hash: None,
                device_key: None,
                a: MOCK_A.to_string(),
            }
        );
    }

    #[test]
    fn test_verify_responds_predictably() {
        let client = SrpClient::<User>::new(
            User::new("us-west-2_abc", "test", "password"),
            "client_id",
            None,
        );

        assert_eq!(
            client.verify(MOCK_SECRET_BLOCK, "user_id", MOCK_SALT, MOCK_B),
            Ok(VerificationParameters {
                password_claim_secret_block: MOCK_SECRET_BLOCK.into(),
                password_claim_signature: "CdMptiJvn5EyrPYBBc8Ee1MbWh0t4uxdfnQ6TwEuAEI="
                    .to_string(),
                secret_hash: None,
                timestamp: "Mon Feb 10 18:30:12 UTC 2025".to_string(),
            })
        );
    }

    #[test]
    fn test_verify_handles_odd_length_values() {
        let client = SrpClient::<User>::new(
            User::new("us-west-2_abc", "test", "password"),
            "client_id",
            None,
        );

        assert_eq!(
            client.verify(
                MOCK_SECRET_BLOCK,
                "user_id",
                // Notice that `b` and `salt` are hex strings which have an odd length!
                "36ef01c",
                "36ef01c"
            ),
            Ok(VerificationParameters {
                password_claim_secret_block: MOCK_SECRET_BLOCK.into(),
                password_claim_signature: "uHIrGhJ/thL3TGJn7o0wxBZCJdRGTBfBqiqziAD3DQU="
                    .to_string(),
                secret_hash: None,
                timestamp: "Mon Feb 10 18:30:12 UTC 2025".to_string(),
            })
        );
    }
}
