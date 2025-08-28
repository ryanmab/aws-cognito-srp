use aws_sdk_cognitoidentityprovider::operation::confirm_device::ConfirmDeviceOutput;
use aws_sdk_cognitoidentityprovider::operation::initiate_auth::InitiateAuthOutput;
use aws_sdk_cognitoidentityprovider::operation::respond_to_auth_challenge::RespondToAuthChallengeOutput;
use aws_sdk_cognitoidentityprovider::types::builders::DeviceSecretVerifierConfigTypeBuilder;
use aws_sdk_cognitoidentityprovider::types::{AuthFlowType, ChallengeNameType};
use dotenvy_macro::dotenv;

use aws_cognito_srp::{
    DeviceAuthenticationParameters, PasswordVerifierParameters, SrpClient,
    TrackedDevice, User, UserAuthenticationParameters, VerificationParameters,
};

pub async fn send_initiate_auth_request(
    cognito: &aws_sdk_cognitoidentityprovider::Client,
    srp_client: &SrpClient<User>,
    parameters: UserAuthenticationParameters,
    device_key: Option<&String>,
) -> InitiateAuthOutput {
    let mut builder = cognito
        .initiate_auth()
        .auth_flow(AuthFlowType::UserSrpAuth)
        .client_id(dotenv!("CLIENT_ID"))
        .auth_parameters("SRP_A", parameters.a)
        .auth_parameters("USERNAME", dotenv!("USER_EMAIL"));

    if let Some(secret_hash) = srp_client.get_secret_hash() {
        builder = builder.auth_parameters("SECRET_HASH", secret_hash);
    }

    if let Some(device_key) = device_key {
        builder = builder.auth_parameters("DEVICE_KEY", device_key);
    }

    builder
        .send()
        .await
        .expect("Request to initiate auth with user SRP should succeed")
}

pub async fn send_password_verifier_auth_challenge_request(
    cognito: &aws_sdk_cognitoidentityprovider::Client,
    srp_client: &SrpClient<User>,
    user_id: &String,
    parameters: VerificationParameters,
    session: Option<String>,
    device_key: Option<&String>,
) -> RespondToAuthChallengeOutput {
    let mut builder = cognito
        .respond_to_auth_challenge()
        .challenge_name(ChallengeNameType::PasswordVerifier)
        .set_session(session)
        .client_id(dotenv!("CLIENT_ID"))
        .challenge_responses("USERNAME", user_id)
        .challenge_responses(
            "PASSWORD_CLAIM_SECRET_BLOCK",
            parameters.password_claim_secret_block,
        )
        .challenge_responses(
            "PASSWORD_CLAIM_SIGNATURE",
            parameters.password_claim_signature,
        )
        .challenge_responses("TIMESTAMP", &parameters.timestamp);

    if let Some(secret_hash) = srp_client.get_secret_hash() {
        builder = builder.challenge_responses("SECRET_HASH", secret_hash);
    }

    if let Some(device_key) = device_key {
        builder = builder.challenge_responses("DEVICE_KEY", device_key);
    }

    builder
        .send()
        .await
        .expect("Responding to the auth challenge should succeed")
}

pub async fn send_confirm_device_request(
    cognito: &aws_sdk_cognitoidentityprovider::Client,
    device_key: &String,
    access_token: &String,
    parameters: &PasswordVerifierParameters,
) -> ConfirmDeviceOutput {
    cognito
        .confirm_device()
        .device_key(device_key)
        .device_name("Test Device")
        .access_token(access_token)
        .device_secret_verifier_config(
            DeviceSecretVerifierConfigTypeBuilder::default()
                .password_verifier(&parameters.verifier)
                .salt(&parameters.salt)
                .build(),
        )
        .send()
        .await
        .expect("Confirming the device should succeed")
}

pub async fn send_device_srp_auth_challenge_request(
    cognito: &aws_sdk_cognitoidentityprovider::Client,
    srp_client: &SrpClient<TrackedDevice>,
    parameters: DeviceAuthenticationParameters,
    user_id: &String,
    session: Option<String>,
) -> RespondToAuthChallengeOutput {
    let mut builder = cognito
        .respond_to_auth_challenge()
        .challenge_responses("SRP_A", parameters.a)
        .challenge_responses("USERNAME", user_id)
        .challenge_responses("DEVICE_KEY", parameters.device_key)
        .set_session(session)
        .client_id(dotenv!("CLIENT_ID"))
        .challenge_name(ChallengeNameType::DeviceSrpAuth);

    if let Some(secret_hash) = srp_client.get_secret_hash(user_id) {
        builder = builder.challenge_responses("SECRET_HASH", secret_hash);
    }

    builder
        .send()
        .await
        .expect("Responding to the auth challenge should succeed")
}

pub async fn send_device_password_verifier_auth_challenge_request(
    cognito: &aws_sdk_cognitoidentityprovider::Client,
    srp_client: &SrpClient<TrackedDevice>,
    user_id: &String,
    parameters: VerificationParameters,
    session: Option<String>,
    device_key: Option<String>,
) -> RespondToAuthChallengeOutput {
    let mut builder = cognito
        .respond_to_auth_challenge()
        .challenge_name(ChallengeNameType::DevicePasswordVerifier)
        .set_session(session)
        .client_id(dotenv!("CLIENT_ID"))
        .challenge_responses("USERNAME", user_id)
        .challenge_responses(
            "PASSWORD_CLAIM_SECRET_BLOCK",
            parameters.password_claim_secret_block,
        )
        .challenge_responses(
            "PASSWORD_CLAIM_SIGNATURE",
            parameters.password_claim_signature,
        )
        .challenge_responses("TIMESTAMP", &parameters.timestamp);

    if let Some(secret_hash) = srp_client.get_secret_hash(user_id) {
        builder = builder.challenge_responses("SECRET_HASH", secret_hash);
    }

    if let Some(device_key) = device_key {
        builder = builder.challenge_responses("DEVICE_KEY", device_key);
    }

    builder
        .send()
        .await
        .expect("Responding to the auth challenge should succeed")
}
