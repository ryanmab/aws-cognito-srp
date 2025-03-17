use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use digest::{Digest, Mac, Output};
use log::info;
use num_bigint::BigUint;
use sha2::Sha256;

use crate::client::helper::{
    compute_k, compute_pub_a, compute_pub_b, compute_s, compute_u, compute_x,
    generate_key_derive_data, generate_password, generate_salt, get_timestamp, left_pad,
    left_pad_to_even_length,
};
use crate::client::private;
use crate::client::{
    AuthParameters, HmacSha256, PasswordVerifierParameters, VerificationParameters,
};
use crate::constant::{G, N};
use crate::{Credentials, SrpClient, SrpError};

/// A **device** which is tracked against a user in the AWS Cognito user pool.
///
/// This device has previously been confirmed, so, if authenticated correctly, may
/// allow the user to bypass some MFA challenges during the authentication flow (depending
/// on user pool configuration)
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct TrackedDevice {
    /// The ID of the AWS Cognito User Pool the device is registered with.
    ///
    /// The format enforced by AWS Cognito is: `<region>_<pool id>`.
    ///
    /// For example: `us-east-1_SqmNeowUdp`.
    pool_id: String,

    /// The username of the **user** who owns the registered device.
    username: String,

    device_group_key: String,
    device_key: String,
    device_password: String,
}

impl private::Sealed for TrackedDevice {}
impl Credentials for TrackedDevice {}

/// A **device** which is not yet tracked against a user in the AWS Cognito user pool.
///
/// This device has not previously been confirmed, and thus does not have a password,
/// and is not yet associated with a user (so cannot be used to bypass MFA challenges).
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct UntrackedDevice {
    /// The ID of the AWS Cognito User Pool the device is registered with.
    ///
    /// The format enforced by AWS Cognito is: `<region>_<pool id>`.
    ///
    /// For example: `us-east-1_SqmNeowUdp`.
    pool_id: String,

    device_group_key: String,
    device_key: String,
}

impl private::Sealed for UntrackedDevice {}
impl Credentials for UntrackedDevice {}

impl UntrackedDevice {
    #[must_use]
    pub fn new(pool_id: &str, device_group_key: &str, device_key: &str) -> Self {
        UntrackedDevice {
            pool_id: pool_id.to_string(),
            device_group_key: device_group_key.to_string(),
            device_key: device_key.to_string(),
        }
    }

    /// Convert the untracked device into a tracked device.
    ///
    /// This requires:
    /// 1. The **device password** (the random password generated for the device during
    ///    confirmation)
    /// 2. The **username** of the user who the device is remembered with.
    pub fn into_tracked(self, username: &str, device_password: &str) -> TrackedDevice {
        TrackedDevice {
            pool_id: self.pool_id,
            username: username.to_string(),
            device_group_key: self.device_group_key,
            device_key: self.device_key,
            device_password: device_password.to_string(),
        }
    }
}

impl TrackedDevice {
    #[must_use]
    pub fn new(
        pool_id: &str,
        username: &str,
        device_group_key: &str,
        device_key: &str,
        device_password: &str,
    ) -> Self {
        TrackedDevice {
            pool_id: pool_id.to_string(),
            username: username.to_string(),
            device_group_key: device_group_key.to_string(),
            device_key: device_key.to_string(),
            device_password: device_password.to_string(),
        }
    }
}

impl SrpClient<TrackedDevice> {
    /// Generate the authentication parameters for the initial `InitiateAuth` request.
    ///
    /// This begins the SRP authentication flow with AWS Cognito, and exchanges the various
    /// initial public parameters which can then be used to validate the user's password.
    pub fn get_auth_parameters(&self) -> AuthParameters {
        let TrackedDevice {
            username,
            device_key,
            ..
        } = &self.credentials;

        info!(
            d = device_key.as_str();
            "Generating auth parameters for device"
        );

        AuthParameters {
            a: hex::encode(compute_pub_a(&self.a)),
            device_key: Some(device_key.into()),
            username: None,
            secret_hash: self.get_secret_hash(username, &self.client_id),
        }
    }

    /// Generate the challenge response parameters for the `DEVICE_PASSWORD_VERIFIER` challenge
    /// issued by AWS Cognito in response to the `RespondToAuthChallenge` request.
    ///
    /// These parameters verify to AWS Cognito that the password known by the client is correct.
    pub fn verify(
        &self,
        secret_block: &str,
        user_id: &str,
        salt: &str,
        b: &str,
    ) -> Result<VerificationParameters, SrpError> {
        let key = self.get_device_authentication_key(
            &hex::decode(left_pad_to_even_length(b, '0')).map_err(|err| {
                SrpError::InvalidArgument(format!("Invalid SRP_B. Received '{}'", err))
            })?,
            &hex::decode(left_pad_to_even_length(salt, '0')).map_err(|err| {
                SrpError::InvalidArgument(format!("Invalid salt. Received '{}'", err))
            })?,
        )?;

        let timestamp = get_timestamp();

        let mut msg: Vec<u8> = vec![];
        msg.extend_from_slice(self.credentials.device_group_key.as_bytes());
        msg.extend_from_slice(self.credentials.device_key.as_bytes());
        msg.extend_from_slice(&BASE64.decode(secret_block).map_err(|err| {
            SrpError::InvalidArgument(format!("Invalid base64 secret block. Received '{}'", err))
        })?);
        msg.extend_from_slice(timestamp.as_bytes());

        let mut h256mac = HmacSha256::new_from_slice(&key)?;
        h256mac.update(&msg);
        let signature = BASE64.encode(h256mac.finalize().into_bytes());

        info!(user_id, device_key = self.credentials.device_key.as_str(); "Generated verification parameters for device.");

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
    fn get_device_authentication_key(&self, b: &[u8], salt: &[u8]) -> Result<Vec<u8>, SrpError> {
        let identity = self.compute_identity::<Sha256>(&self.credentials.device_password);

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
    /// For AWS Cognito this is the SHA256 of `<device group key><device key>:<device password>`.
    fn compute_identity<D: Digest>(&self, password: &str) -> Output<D> {
        let TrackedDevice {
            device_group_key,
            device_key,
            ..
        } = &self.credentials;

        let mut d = D::new();
        d.update(device_group_key);
        d.update(device_key);
        d.update(":");
        d.update(password);

        d.finalize()
    }
}

impl SrpClient<UntrackedDevice> {
    /// Generate a password, and the verifier parameters (verifier and salt) for the
    /// `ConfirmDevice` request.
    ///
    /// This generates a (new) random password, along with a salt and verifier which
    /// AWS Cognito records, and can be used during the authentication flow later to validate
    /// the password provided to authenticate.
    pub fn get_password_verifier(&self) -> PasswordVerifierParameters {
        let random_password = generate_password();
        let salt = generate_salt();

        // Setup the hash for the device
        let device_hash = self.compute_identity::<Sha256>(&random_password);

        // Compute the verifier, which consists of the salt and the hash
        let mut hasher = Sha256::new();
        hasher.update(&salt);
        hasher.update(device_hash);
        let password_salted = hasher.finalize();

        let password_verifier = left_pad(
            &G.modpow(&BigUint::from_bytes_be(password_salted.as_slice()), &N)
                .to_bytes_be(),
            0,
        );

        info!(device_key = self.credentials.device_key.as_str(); "Generated verifier and random password for device.");

        PasswordVerifierParameters {
            verifier: BASE64.encode(password_verifier.as_slice()),
            salt: BASE64.encode(salt.as_slice()),
            password: random_password,
        }
    }

    /// Compute identity (`I`) variable in the SRP protocol.
    ///
    /// For AWS Cognito this is the SHA256 of `<device group key><device key>:<device password>`.
    fn compute_identity<D: Digest>(&self, password: &str) -> Output<D> {
        let UntrackedDevice {
            device_group_key,
            device_key,
            ..
        } = &self.credentials;

        let mut d = D::new();
        d.update(device_group_key);
        d.update(device_key);
        d.update(":");
        d.update(password);

        d.finalize()
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use crate::PasswordVerifierParameters;

    use super::{SrpClient, TrackedDevice, UntrackedDevice, VerificationParameters};

    const MOCK_A: &str = "e13e5e4bdcb2670718d3141be1c00299211c244b6e0ec0c404e5c6c126fcefcbf3f5f165822a56e25f9906be1fba382a48eeb6b3915f12c91934e6ac4f18f0e2d20fdb77cba8ca0c5bbfda16c05686a6820ade1a5eeb1dfc551b96bed06ed8b14b218127d4d84f32ee9aa6fc32d100240a914d8708dd5bb68827a1a4be3dc4a129e1c08a4787739f6041dd966d1996c9ced9f72960f3e3c0e802d04beaa2e71c9af5a7d7dd1f3c695a80db20eb069f5bda0356ba9851a41a5c55ed68636e0aedacb1f7d370f25ef9186f5112866ad71aa825fda6991ac8d262b7a2765af07b65735cdca7e8d71f3b7d5c5d97297561e157ccdc40e034ecc71a38e534b1a2456962b5218bd533774462220d18c2ce8fb36e40fc61710f202df65d378eed2a8d811bcce5b2ee5013e3e8a3b3fde40dfb90f4d1e9eac28b3f396edeb119c98dae8d65aa17287767c4a38113b698312ff5ac351d10a5171e01ddf8fd1245c78716cf1610a60d0d82f94def26f646f91a347353276289af65f6c0bb6f95a84fa47c37";

    const MOCK_B: &str = "36ef01c6dde9fe503da333b1acc758ba";

    const MOCK_SALT: &str = "36ef01c6dde9fe503da333b1acc758ba";

    const MOCK_SECRET_BLOCK: &str = "9ae77ec7154c14dcc487b47707fee4b4920cb96d8a8c045e4c8df879a7b375524aa736acdec6c9ad4ea606774d00621b";

    const MOCK_USER_ID: &str = "abc-1234-678";

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
        let client = SrpClient::new(
            TrackedDevice::new(
                "us-west-2_abc",
                "username",
                "mock-device-group-key",
                "mock-device-key",
                "password",
            ),
            "client_id",
            None,
        );

        assert_eq!(
            client.get_auth_parameters(),
            crate::client::AuthParameters {
                username: None,
                secret_hash: None,
                device_key: Some("mock-device-key".to_string()),
                a: MOCK_A.to_string(),
            }
        );
    }

    #[test]
    fn test_verify_responds_predictably() {
        let client = SrpClient::new(
            TrackedDevice::new(
                "us-west-2_abc",
                "username",
                "mock-device-group-key",
                "mock-device-key",
                "password",
            ),
            "client_id",
            None,
        );

        assert_eq!(
            client.verify(MOCK_SECRET_BLOCK, MOCK_USER_ID, MOCK_SALT, MOCK_B),
            Ok(VerificationParameters {
                password_claim_secret_block: MOCK_SECRET_BLOCK.into(),
                password_claim_signature: "KSRih5nKU36kjmcZh9Ig9aR25MWPtJpWAurpHg+Xo90="
                    .to_string(),
                secret_hash: None,
                timestamp: "Mon Feb 10 18:30:12 UTC 2025".to_string(),
            })
        );
    }

    #[test]
    fn test_password_verifier_responds_predictably() {
        let client = SrpClient::new(
            UntrackedDevice::new("us-west-2_abc", "mock-device-group-key", "mock-device-key"),
            "client_id",
            None,
        );

        assert_eq!(
            client.get_password_verifier(),
            PasswordVerifierParameters {
                verifier: "HbS1w1zEsZfmlcGdYPU5dFtGB/N6ecmrCu4ztV6PWkmGwrN588f3Iu+iwlayKIjnJDMjGgcJYrlDe+RvEWXifw6KnZiVhO2AS+qtI3Q/JbMPFjtcFECdBiD8vWC7g0rnoiHWlmk7vPMy+MJjBqVNqQXIREE+becM+NcZy+thnjgiziR6XCce0Ta46ZJEbaCLmtunuoxj4u1Q3/vdyK6kYGR7tJNSzG75MhLN0DHeUJifIc4UszuB++aSerll+nWrKSsjO8Q3YcVeboQTlGJhbS7n5wGXR/aiYtGwLi6YcdqbCH1ogh8je2KHBcQMCtH+KA7+73Oq9l2p7Fonud/+yFRLqfu4rskBVkS6mzpUuXws1WkG5FmWSnOsGUgja8ZBIaf8S9/cfYp7ciYefF2aWcQwigp5TLytosgLYBx6nvWz+n1k/OXiLmm0yQMS/b1If8G5TvVqvY8Qu3IzBugBSvLSF+UfgVxZV+xVTO5ykKPQkH4B+nQZtQ/lZNZyNJJT".to_string(),
                salt: "MDAwMDAwMDAwMDAwMDAwMDAxMDAwMDAwMDAwMDAwMDA=".to_string(),
                password: "AAAAAAAAAAABAAAAAAAAAAIAAAAAAAAAAwAAAAAAAAAEAAAAAAAAAA==".to_string(),
            }
        )
    }

    #[test]
    fn test_verify_handles_odd_length_values() {
        let client = SrpClient::new(
            TrackedDevice::new(
                "us-west-2_abc",
                "username",
                "mock-device-group-key",
                "mock-device-key",
                "password",
            ),
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
                password_claim_signature: "cKgJ7Fze+M1NZQe5aMU5qj60nUlaRu+Q1ElXX3qMVv0="
                    .to_string(),
                secret_hash: None,
                timestamp: "Mon Feb 10 18:30:12 UTC 2025".to_string(),
            })
        );
    }
}
