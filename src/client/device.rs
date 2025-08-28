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
    /// Create a new untracked device.
    ///
    /// This is a device which has not yet been confirmed with the AWS Cognito User Pool, and
    /// thus does not have a password.
    #[must_use]
    pub fn new(pool_id: &str, device_group_key: &str, device_key: &str) -> Self {
        Self {
            pool_id: pool_id.to_string(),
            device_group_key: device_group_key.to_string(),
            device_key: device_key.to_string(),
        }
    }

    /// Convert the untracked device into a tracked device.
    ///
    /// This requires **device password** (the random password generated for the device during
    /// confirmation).
    #[must_use]
    pub fn into_tracked(self, device_password: &str) -> TrackedDevice {
        TrackedDevice::from_untracked(&self, device_password)
    }
}

impl TrackedDevice {
    /// Create a new tracked device.
    ///
    /// This is a device which has previously been confirmed, and thus has a password.
    ///
    /// When configured correctly, this device may be allowed to bypass some MFA challenges (depending
    /// on the configuration of the AWS Cognito User Pool).
    #[must_use]
    pub fn new(
        pool_id: &str,
        device_group_key: &str,
        device_key: &str,
        device_password: &str,
    ) -> Self {
        Self {
            pool_id: pool_id.to_string(),
            device_group_key: device_group_key.to_string(),
            device_key: device_key.to_string(),
            device_password: device_password.to_string(),
        }
    }

    /// Convert the untracked device into a tracked device.
    ///
    /// This requires:
    /// 1. The **device password** (the random password generated for the device during
    ///    confirmation)
    /// 2. The **username** of the user who the device is remembered with.
    #[must_use]
    pub fn from_untracked(untracked: &UntrackedDevice, device_password: &str) -> Self {
        Self::new(
            &untracked.pool_id,
            &untracked.device_group_key,
            &untracked.device_key,
            device_password,
        )
    }
}

impl SrpClient<TrackedDevice> {
    /// Generate the authentication parameters for the initial `InitiateAuth` request.
    ///
    /// This begins the SRP authentication flow with AWS Cognito, and exchanges the various
    /// initial public parameters which can then be used to validate the user's password.
    pub fn get_auth_parameters(&self) -> AuthParameters {
        let TrackedDevice { device_key, .. } = &self.credentials;

        info!(
            d = device_key.as_str();
            "Generating auth parameters for device"
        );

        AuthParameters {
            a: hex::encode(compute_pub_a(&self.a)),
            device_key: Some(device_key.into()),
            username: None,
        }
    }

    /// Get the secret hash to be used on login and challenge requests to AWS Cognito.
    ///
    /// This is only required if your App client is configured with a client secret (and that is
    /// provided when creating the SRP client).
    ///
    /// The resulting hash should be provided as the `SECRET_HASH` parameter in the `InitiateAuth`
    /// and `RespondToAuthChallenge` requests to [AWS Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/signing-up-users-in-your-app.html#cognito-user-pools-computing-secret-hash).
    #[must_use]
    pub fn get_secret_hash(&self, user_id: &str) -> Option<String> {
        self.get_secret_hash_for_user_id(user_id, &self.client_id)
    }

    /// Generate the challenge response parameters for the `DEVICE_PASSWORD_VERIFIER` challenge
    /// issued by AWS Cognito in response to the `RespondToAuthChallenge` request.
    ///
    /// These parameters verify to AWS Cognito that the password known by the client is correct.
    ///
    /// ## Errors
    ///
    /// Returns an error if any of the input values are invalid. For example, if the `b` or `salt`
    /// values are not valid hex strings.
    pub fn verify(
        &self,
        secret_block: &str,
        salt: &str,
        b: &str,
    ) -> Result<VerificationParameters, SrpError> {
        let key = self.get_device_authentication_key(
            &hex::decode(left_pad_to_even_length(b, '0')).map_err(|err| {
                SrpError::InvalidArgument(format!("Invalid SRP_B. Received '{err}'"))
            })?,
            &hex::decode(left_pad_to_even_length(salt, '0')).map_err(|err| {
                SrpError::InvalidArgument(format!("Invalid salt. Received '{err}'"))
            })?,
        )?;

        let timestamp = get_timestamp();

        let mut msg: Vec<u8> = vec![];
        msg.extend_from_slice(self.credentials.device_group_key.as_bytes());
        msg.extend_from_slice(self.credentials.device_key.as_bytes());
        msg.extend_from_slice(&BASE64.decode(secret_block).map_err(|err| {
            SrpError::InvalidArgument(format!("Invalid base64 secret block. Received '{err}'"))
        })?);
        msg.extend_from_slice(timestamp.as_bytes());

        let mut h256mac = HmacSha256::new_from_slice(&key)?;
        h256mac.update(&msg);
        let signature = BASE64.encode(h256mac.finalize().into_bytes());

        info!(device_key = self.credentials.device_key.as_str(); "Generated verification parameters for device.");

        Ok(VerificationParameters {
            timestamp,
            password_claim_secret_block: secret_block.into(),
            password_claim_signature: signature,
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
    #[must_use]
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
    use crate::PasswordVerifierParameters;

    use super::{SrpClient, TrackedDevice, UntrackedDevice, VerificationParameters};

    const MOCK_A: &str = "b1ce118779e27c1c015d7a226ecae2ea1fcd017049e4f5c6f9908c686d496dce12a1c017a7523d43e2f3a6bb7e75e266bab0471e0720030edb64d8b5aef428356bc72198d41d319cf36eb0c4b4063fb99f90bc3b25b0d1196f84836bc05be0dfe1e6d1e21ba4c77098f6e6119127981395b0f4da67e26f63ecbfb2ded5d9c091c9850c08f0c372e5101df27967250254d6748a75c9be2f59324d31241f950d79224af0d5ff1c169af541b04a063bd0d4f79216a9da1e1874bc041b97ca2d456310f0b29f3644eca4d0e0c21660cbc5774a7319746bf53024a3bbb9c1251002854d1e6fac951d3a160771cdaf681a95e8cd51eb0630c825cd6227f22edefd35b3789df41dfca6cbd4d90e90ec7e38d3cbdf2b5f3534b016267f6a42190690d4225131811c6ea3b8265cff2fc44497887995eb95357747c3db40dab7199af3b9cbaba28a75d800d809421c5da1b0a24ec3120b3738750dcd42a61d1e9d272118ec2e6db632c241ab33558502dc9bbac1f4a34b3243082b89dcc0620a626d83a483";

    const MOCK_B: &str = "36ef01c6dde9fe503da333b1acc758ba";

    const MOCK_SALT: &str = "36ef01c6dde9fe503da333b1acc758ba";

    const MOCK_SECRET_BLOCK: &str = "9ae77ec7154c14dcc487b47707fee4b4920cb96d8a8c045e4c8df879a7b375524aa736acdec6c9ad4ea606774d00621b";

    #[test]
    fn test_auth_parameters_generates_successfully() {
        let client = SrpClient::new(
            TrackedDevice::new(
                "us-west-2_abc",
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
                "mock-device-group-key",
                "mock-device-key",
                "password",
            ),
            "client_id",
            None,
        );

        assert_eq!(
            client.verify(MOCK_SECRET_BLOCK, MOCK_SALT, MOCK_B),
            Ok(VerificationParameters {
                password_claim_secret_block: MOCK_SECRET_BLOCK.into(),
                password_claim_signature: "O9uSej4H1B4or3Zc7Q4+KxuSvOaEfuq2a7Ye4d16fmo="
                    .to_string(),
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
                verifier: "MlDC+806aWjrGBiwORRZRArlVzQm2cOadTDuNvXjLR2FVXmNw2aLKzYdBSLtUhVUs2FHx3JGcRLxH8QR0+HYaMgNCysSaPaA+ornRiQLD/I1K5rJpf6WeAMv7R6wr+Nq6+TCun72ime0UZd/CJSlO2JQ4Jdq55VuvZpBAZAhyEWDGmNQRe11WbxuO8tNSnsqSnUxn9+RYq+gXOAjdjv1Nn5zvFHTipZyOfUCYDoXtcjfbdkgzDwujTyb7TKeUvqc98/CJoa5b34ukLURIOvVXVYnXCaU4ArYZaI/zNtEdKQqA44kW+ZJSWliFG9nm/H8T8a6rIdwims9PZDau4Xm9968LqDdOB0bKOY8TyeL8merbkf0GPGculp9twCBKwVDcz10JRipDqFiU5byYeBPSj2ucX5TX+dcBhbMqjXXhQNPL1fmd14n2VmmLLSAJm8Tss+h3eqMBsSc4UkzHlyX6MeqsqmEegFGTrmGoyID3LORfk0hzFCjIpHJL6u+WCm1".to_string(),
                salt: "MDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDEwMTAxMDE=".to_string(),
                password: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==".to_string(),
            }
        );
    }

    #[test]
    fn test_verify_handles_odd_length_values() {
        let client = SrpClient::new(
            TrackedDevice::new(
                "us-west-2_abc",
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
                // Notice that `b` and `salt` are hex strings which have an odd length!
                "36ef01c",
                "36ef01c"
            ),
            Ok(VerificationParameters {
                password_claim_secret_block: MOCK_SECRET_BLOCK.into(),
                password_claim_signature: "eXYI/hzMa/5YWYSk1NFcDMOOBAOg+juflcjl38+xx4I="
                    .to_string(),
                timestamp: "Mon Feb 10 18:30:12 UTC 2025".to_string(),
            })
        );
    }
}
