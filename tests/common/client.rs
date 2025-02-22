use dotenvy_macro::dotenv;

use aws_cognito_srp::{TrackedDevice, UntrackedDevice, User};

use crate::common;

pub fn get_user_srp_client() -> aws_cognito_srp::SrpClient<User, rand::prelude::ThreadRng> {
    common::get_srp_client(
        User {
            pool_id: dotenv!("POOL_ID").to_string(),
            username: dotenv!("USER_EMAIL").to_string(),
            password: dotenv!("USER_PASSWORD").to_string(),
        },
        dotenv!("CLIENT_ID"),
        Some(dotenv!("CLIENT_SECRET")),
    )
}

pub fn get_tracked_device_srp_client(
    device_key: String,
    device_group_key: String,
    device_password: String,
) -> aws_cognito_srp::SrpClient<TrackedDevice, rand::prelude::ThreadRng> {
    common::get_srp_client(
        TrackedDevice {
            pool_id: dotenv!("POOL_ID").to_string(),
            username: dotenv!("USER_EMAIL").to_string(),
            device_key,
            device_group_key,
            device_password,
        },
        dotenv!("CLIENT_ID"),
        Some(dotenv!("CLIENT_SECRET")),
    )
}

pub fn get_untracked_device_srp_client(
    device_key: String,
    device_group_key: String,
) -> aws_cognito_srp::SrpClient<UntrackedDevice, rand::prelude::ThreadRng> {
    common::get_srp_client(
        UntrackedDevice {
            pool_id: dotenv!("POOL_ID").to_string(),
            device_key,
            device_group_key,
        },
        dotenv!("CLIENT_ID"),
        Some(dotenv!("CLIENT_SECRET")),
    )
}
