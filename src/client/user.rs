use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use digest::{Digest, Mac, Output};
use log::info;
use sha2::Sha256;

use crate::client::helper::{
    compute_k, compute_pub_a, compute_pub_b, compute_s, compute_u, compute_x,
    generate_key_derive_data, get_timestamp, left_pad, left_pad_to_even_length,
};
use crate::client::{HmacSha256, VerificationParameters, private};
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

/// The parameters required to initiate an authentication flow with AWS Cognito, when using the
/// `USER_SRP_AUTH` flow type.
///
/// For the full request structure see documentation: [InitiateAuth](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html)
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct UserAuthenticationParameters {
    /// The **public** `A` for the client.
    pub a: String,

    /// The username of the user - this is the one provided during
    /// instantiation of the SRP client.
    pub username: String,
}

impl SrpClient<User> {
    /// Generate the authentication parameters for the initial `InitiateAuth` request.
    ///
    /// This begins the SRP authentication flow with AWS Cognito, and exchanges the various
    /// initial public parameters which can then be used to validate the user's password.
    pub fn get_auth_parameters(&self) -> UserAuthenticationParameters {
        let User { username, .. } = &self.credentials;

        info!(username = username.as_str(); "Generating auth parameters for user");

        UserAuthenticationParameters {
            username: username.into(),
            a: hex::encode(compute_pub_a(&self.a)),
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
    pub fn get_secret_hash(&self) -> Option<String> {
        self.get_secret_hash_for_user_id(&self.credentials.username, &self.client_id)
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
    use super::{SrpClient, User, VerificationParameters};

    const MOCK_A: &str = "b1ce118779e27c1c015d7a226ecae2ea1fcd017049e4f5c6f9908c686d496dce12a1c017a7523d43e2f3a6bb7e75e266bab0471e0720030edb64d8b5aef428356bc72198d41d319cf36eb0c4b4063fb99f90bc3b25b0d1196f84836bc05be0dfe1e6d1e21ba4c77098f6e6119127981395b0f4da67e26f63ecbfb2ded5d9c091c9850c08f0c372e5101df27967250254d6748a75c9be2f59324d31241f950d79224af0d5ff1c169af541b04a063bd0d4f79216a9da1e1874bc041b97ca2d456310f0b29f3644eca4d0e0c21660cbc5774a7319746bf53024a3bbb9c1251002854d1e6fac951d3a160771cdaf681a95e8cd51eb0630c825cd6227f22edefd35b3789df41dfca6cbd4d90e90ec7e38d3cbdf2b5f3534b016267f6a42190690d4225131811c6ea3b8265cff2fc44497887995eb95357747c3db40dab7199af3b9cbaba28a75d800d809421c5da1b0a24ec3120b3738750dcd42a61d1e9d272118ec2e6db632c241ab33558502dc9bbac1f4a34b3243082b89dcc0620a626d83a483";

    const MOCK_B: &str = "36ef01c6dde9fe503da333b1acc758ba";

    const MOCK_SALT: &str = "36ef01c6dde9fe503da333b1acc758ba";

    const MOCK_SECRET_BLOCK: &str = "9ae77ec7154c14dcc487b47707fee4b4920cb96d8a8c045e4c8df879a7b375524aa736acdec6c9ad4ea606774d00621b";

    #[test]
    fn test_auth_parameters_generates_successfully() {
        let client = SrpClient::<User>::new(
            User::new("us-west-2_abc", "test", "password"),
            "client_id",
            None,
        );

        assert_eq!(
            client.get_auth_parameters(),
            crate::client::user::UserAuthenticationParameters {
                username: "test".to_string(),
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
                password_claim_signature: "apNSb5GZpJciVc6cVNkDf4elCMoWUZcH4aukLlMPiFA="
                    .to_string(),
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
                password_claim_signature: "bVzjSe43mY37A6ZuzEVU5cr6QY1WeV3BPfdVJo0c2/8="
                    .to_string(),
                timestamp: "Mon Feb 10 18:30:12 UTC 2025".to_string(),
            })
        );
    }
}
