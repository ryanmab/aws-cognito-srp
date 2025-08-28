use dotenvy_macro::dotenv;

use aws_cognito_srp::{TrackedDevice, UntrackedDevice, User};

use crate::common;

pub fn get_user_srp_client() -> aws_cognito_srp::SrpClient<User> {
    common::get_srp_client(
        User::new(
            dotenv!("POOL_ID"),
            dotenv!("USER_EMAIL"),
            dotenv!("USER_PASSWORD"),
        ),
        dotenv!("CLIENT_ID"),
        Some(dotenv!("CLIENT_SECRET")),
    )
}

pub fn get_tracked_device_srp_client(
    device_key: String,
    device_group_key: String,
    device_password: String,
) -> aws_cognito_srp::SrpClient<TrackedDevice> {
    common::get_srp_client(
        TrackedDevice::new(
            dotenv!("POOL_ID"),
            &device_group_key,
            &device_key,
            &device_password,
        ),
        dotenv!("CLIENT_ID"),
        Some(dotenv!("CLIENT_SECRET")),
    )
}

pub fn get_untracked_device_srp_client(
    device_key: String,
    device_group_key: String,
) -> aws_cognito_srp::SrpClient<UntrackedDevice> {
    common::get_srp_client(
        UntrackedDevice::new(dotenv!("POOL_ID"), &device_group_key, &device_key),
        dotenv!("CLIENT_ID"),
        Some(dotenv!("CLIENT_SECRET")),
    )
}
