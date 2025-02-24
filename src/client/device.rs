use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use digest::{Digest, Mac, Output};
use log::info;
use num_bigint::BigUint;
use rand::RngCore;
use sha2::Sha256;

use crate::client::helper::{
    compute_k, compute_pub_a, compute_pub_b, compute_s, compute_u, compute_x,
    generate_key_derive_data, generate_password, generate_salt, get_timestamp, left_pad,
    left_pad_to_even_length,
};
use crate::client::{
    AuthParameters, HmacSha256, PasswordVerifierParameters, VerificationParameters,
};
use crate::constant::{G, N};
use crate::{Credentials, SrpClient, SrpError};
use crate::client::private;

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

impl<R: RngCore + Default> SrpClient<TrackedDevice, R> {
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

impl<R: RngCore + Default> SrpClient<UntrackedDevice, R> {
    /// Generate a password, and the verifier parameters (verifier and salt) for the
    /// `ConfirmDevice` request.
    ///
    /// This generates a (new) random password, along with a salt and verifier which
    /// AWS Cognito records, and can be used during the authentication flow later to validate
    /// the password provided to authenticate.
    pub fn get_password_verifier(&self) -> PasswordVerifierParameters {
        let random_password = generate_password(self.rand.borrow_mut());
        let salt = generate_salt(self.rand.borrow_mut());

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

    const MOCK_A: &str = "27f0e74d7714e7985b87807ac0df0df5df93b1d3ff036bb0cd99b41d8dfa6fc522e12b9734f94aafb8c4c04213f8c1b91f049f9e841ad6f6f0ea971fcb76371f4eb88351a702958e14b678b3646578f406e74cfc7f0622c953f31101c80c8d82d7f9319f01148d4d012789d05afe4578f8a7390e763a13bd6a4d96e1c705f38fae9e0ee42cab2042fed2889118baf44dcc11d3d058ac752f652857d30607c891429981b1f2c46231a770765806820cc6bc01a89978b19fba952277346111934af218d3c62be732194a99a3d52d80fe742f7baa4657d6ae0c3f9df6357372fda51fd1c571cfacfad9dd23a382973ec45e0c98e0157abb8fdf64dd204453fdf8eab99c4ccdc9fa7b07df2f4440ff0c26d7267ce0039eaeeb943bf288ca046b00a2609bedb2f512f226800e4b1abb665c039bc2a08332fb40396a558558a68ccc6f4e4cbdb828830facfbf0457cf250d88682e71599e0a2e7e2808ee6f089383a6b298e38cc77970d03577ce10ec398a1198929bf56035d8ed2449cd962a8714dd7";

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
        let client = SrpClient::<TrackedDevice, MockRng>::new(
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
        let client = SrpClient::<TrackedDevice, MockRng>::new(
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
                password_claim_signature: "eJ7lk0Z2fWLgBRkT0r2375/WcR3XywRXN0hyJo7oxfk="
                    .to_string(),
                secret_hash: None,
                timestamp: "Mon Feb 10 18:30:12 UTC 2025".to_string(),
            })
        );
    }

    #[test]
    fn test_password_verifier_responds_predictably() {
        let client = SrpClient::<_, MockRng>::new(
            UntrackedDevice::new(
                "us-west-2_abc",
                "mock-device-group-key",
                "mock-device-key",
            ),
            "client_id",
            None,
        );

        assert_eq!(
            client.get_password_verifier(),
            PasswordVerifierParameters {
                verifier: "GZtMUiE1vS74Q5Itqek8xirkRetCaCxc1Hvsd9YrZXypPXnhOazX4dVMILzdX2t9eJ+A0pdZ/SFgxsnzV+T6stVUopw0uPEmi5xx3/P8h4kVjax4u2sNIeiQ9SytYJlI25L5xJUNQ7zTUj1zK48mD8DQV7jjP0ipYVSaI95Fjfi2Cm7EhxjGz2vCLF+i6GwRlZ3j3Cc5M81VhIVrNLmBBQneCXYz4iLSMJ1x7y4h/DKvx347cApaT7AG2ZaA+CTOxjWdDsCHAAs8/H5vsgMM4ug2HtiHjjqfNDbHElB1iEJKHWyCzNvSY3WLBnpExPWDfTUA13h9grLqjKExilyjXpwvcopzflzDtwgPA1pVuFeU/S+pH1/7LgWv5N3N0/LGZD76ycaZQq926LOdrYFToOFujPmY+0UPbbeSbc/qey/utW8MsAbu452fW/5tlJeUd3Ev5oLyr5erLf0omaaxJ0r/LMnPq4anu+LIcX29r/RjOk+dDk9EiwtrjIVlBBMY".to_string(),
                salt: "MDAwMTAyMDMwNDA1MDYwNzAwMDEwMjAzMDQwNTA2MDc=".to_string(),
                password: "AAECAwQFBgcAAQIDBAUGBwABAgMEBQYHAAECAwQFBgcAAQIDBAUGBw==".to_string(),
            }
        )
    }

    #[test]
    fn test_verify_handles_odd_length_values() {
        let client = SrpClient::<TrackedDevice, MockRng>::new(
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
                password_claim_signature: "47qX0OjCipFsp0wJ9CR1tSU86F8/ua1Z6sxtjiGqSL8="
                    .to_string(),
                secret_hash: None,
                timestamp: "Mon Feb 10 18:30:12 UTC 2025".to_string(),
            })
        );
    }
}
