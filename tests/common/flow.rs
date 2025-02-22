use aws_sdk_cognitoidentityprovider::types::{
    AuthenticationResultType, ChallengeNameType, NewDeviceMetadataType,
};
use rand::Rng;

use aws_cognito_srp::{UntrackedDevice, User};

use crate::common;

pub async fn authenticate_as_user(
    cognito: &aws_sdk_cognitoidentityprovider::Client,
    srp: &aws_cognito_srp::SrpClient<User, impl Rng + Default>,
) -> Option<AuthenticationResultType> {
    let response =
        common::request::send_initiate_auth_request(cognito, srp.get_auth_parameters()).await;

    assert_eq!(
        response.challenge_name,
        Some(ChallengeNameType::PasswordVerifier)
    );

    let auth_session = response.session;

    let challenge_parameters = response
        .challenge_parameters
        .expect("Challenge parameters should be present");

    let user_id = challenge_parameters
        .get("USER_ID_FOR_SRP")
        .expect("Cognito should return a user id for SRP");

    let parameters = srp
        .verify(
            challenge_parameters
                .get("SECRET_BLOCK")
                .expect("Cognito should return a secret block"),
            user_id,
            challenge_parameters
                .get("SALT")
                .expect("Cognito should return a salt for SRP"),
            challenge_parameters
                .get("SRP_B")
                .expect("SRP_B should be present in the response"),
        )
        .expect("Verification parameters should always be returned");

    common::request::send_password_verifier_auth_challenge_request(
        &cognito,
        user_id,
        parameters,
        auth_session,
        None,
    )
    .await
    .authentication_result
}

pub async fn confirm_new_device(
    cognito: &aws_sdk_cognitoidentityprovider::Client,
    srp: &aws_cognito_srp::SrpClient<UntrackedDevice, impl Rng + Default>,
    device_key: &String,
    access_token: &String,
) -> String {
    let verifier = srp.get_password_verifier();

    let response =
        common::request::send_confirm_device_request(cognito, device_key, access_token, &verifier)
            .await;

    assert!(!response.user_confirmation_necessary);

    verifier.password
}

pub async fn authenticate_as_user_and_confirm_device(
    cognito: &aws_sdk_cognitoidentityprovider::Client,
    srp: &aws_cognito_srp::SrpClient<User, impl Rng + Default>,
) -> (String, String, String) {
    let authentication_result = common::flow::authenticate_as_user(&cognito, &srp).await;

    assert!(common::is_authenticated(authentication_result.as_ref()));

    let AuthenticationResultType {
        access_token: Some(access_token),
        new_device_metadata:
            Some(NewDeviceMetadataType {
                device_key,
                device_group_key,
                ..
            }),
        ..
    } = authentication_result
        .as_ref()
        .expect("Authentication result should be present")
    else {
        panic!("All properties should be present in the response, some were missing.");
    };

    let password = confirm_new_device(
        cognito,
        &common::client::get_untracked_device_srp_client(
            device_key.as_ref().unwrap().clone(),
            device_group_key.as_ref().unwrap().clone(),
        ),
        device_key.as_ref().unwrap(),
        access_token,
    )
    .await;

    (
        device_key.as_ref().unwrap().clone(),
        device_group_key.as_ref().unwrap().clone(),
        password,
    )
}
