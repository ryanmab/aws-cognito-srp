mod common;

#[tokio::test]
async fn test_user_sign_in_works() {
    common::setup();

    let authentication_result = common::flow::authenticate_as_user(
        &common::get_cognito_client().await,
        &common::client::get_user_srp_client(),
    )
    .await;

    assert!(common::is_authenticated(authentication_result.as_ref()));
}
