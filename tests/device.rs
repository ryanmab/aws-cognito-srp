use aws_sdk_cognitoidentityprovider::types::ChallengeNameType;

pub mod common;

#[tokio::test]
async fn test_device_sign_in_works() {
    common::setup();

    let cognito = common::get_cognito_client().await;
    let user_srp = common::client::get_user_srp_client();

    let (device_key, device_group_key, password) =
        common::flow::authenticate_as_user_and_confirm_device(&cognito, &user_srp).await;

    let response =
        common::request::send_initiate_auth_request(&cognito, user_srp.get_auth_parameters()).await;

    let challenge_parameters = response
        .challenge_parameters
        .expect("Challenge parameters should be present");

    let auth_session = response.session;
    let user_id = challenge_parameters
        .get("USER_ID_FOR_SRP")
        .expect("Cognito should return a salt for SRP");

    let parameters = user_srp
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

    let response = common::request::send_password_verifier_auth_challenge_request(
        &cognito,
        user_id,
        parameters,
        auth_session.clone(),
        Some(device_key.clone()),
    )
    .await;

    assert_eq!(
        response.challenge_name,
        Some(ChallengeNameType::DeviceSrpAuth)
    );

    let device_srp = common::client::get_tracked_device_srp_client(
        device_key.clone(),
        device_group_key.clone(),
        password,
    );

    let response = common::request::send_device_srp_auth_challenge_request(
        &cognito,
        device_srp.get_auth_parameters(),
        user_id,
        &device_key,
        auth_session,
    )
    .await;

    let auth_session = response.session;

    assert_eq!(
        response.challenge_name,
        Some(ChallengeNameType::DevicePasswordVerifier)
    );

    let challenge_parameters = response
        .challenge_parameters
        .expect("Challenge parameters should be present");

    let user_id = challenge_parameters
        .get("USERNAME")
        .expect("Cognito should return a user id for SRP");

    let parameters = device_srp
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

    let response = common::request::send_device_password_verifier_auth_challenge_request(
        &cognito,
        user_id,
        parameters,
        auth_session,
        Some(device_key),
    )
    .await;

    common::is_authenticated(response.authentication_result.as_ref());
}
