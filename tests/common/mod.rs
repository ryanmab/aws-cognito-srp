use aws_config::BehaviorVersion;
use aws_sdk_cognitoidentityprovider::types::AuthenticationResultType;
use dotenvy::dotenv;
use dotenvy_macro::dotenv;
use rand::prelude::ThreadRng;

use aws_cognito_srp::{Credentials, SrpClient};

pub mod client;
pub mod flow;
pub mod request;

pub fn setup() {
    dotenv().ok();
}

pub fn get_srp_client<C: Credentials>(
    credentials: C,
    client_id: &str,
    client_secret: Option<&str>,
) -> SrpClient<C, ThreadRng> {
    SrpClient::new(credentials, client_id, client_secret)
}

pub async fn get_cognito_client() -> aws_sdk_cognitoidentityprovider::Client {
    aws_sdk_cognitoidentityprovider::Client::new(
        &aws_config::defaults(BehaviorVersion::latest())
            .region(dotenv!("REGION"))
            .load()
            .await,
    )
}

pub fn is_authenticated(authentication_result: Option<&AuthenticationResultType>) -> bool {
    authentication_result.is_some()
        && authentication_result.unwrap().id_token.is_some()
            & authentication_result.unwrap().access_token.is_some()
        && authentication_result.unwrap().refresh_token.is_some()
}
