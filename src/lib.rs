#![crate_name = "aws_cognito_srp"]

//! # AWS Cognito SRP
//!
//! A Rust implementation of the Secure Remote Password (SRP) protocol for AWS Cognito.
//!
//! This includes helpers for **User** (`USER_SRP_AUTH` / `PASSWORD_VERIFIER`) and **Device** (`DEVICE_SRP_AUTH` / `DEVICE_PASSWORD_VERIFIER`) authentication flows, as
//! well as the `ConfirmDevice` flow.
//!
//! ## Usage
//!
//! ```toml
//! [dependencies]
//! aws-cognito-srp = "0.0.2"
//! ```
//!
//! ### User authentication
//!
//! The [authentication flow](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow-methods.html#Built-in-authentication-flow-and-challenges)
//! is described in detail the AWS Cognito documentation.
//!
//! When performing the SRP authentication flow, the correct parameters can be generated for the [InitiateAuth](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html) request, when using the
//! `USER_SRP_AUTH` flow type, and the subsequent [RespondToAuthChallenge](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html) request when the `PASSWORD_VERIFIER` challenge is
//! issued.
//!
//! ```no_run
//! use rand::rngs::ThreadRng;
//! use aws_cognito_srp::{AuthParameters, SrpClient, SrpError, User, VerificationParameters};
//!
//! let client_id = "";
//!
//! // Optional: If your App client is configured with a client secret, AWS Cognito will require that
//! // a secret is provided during the authentication flow (which requires the client secret).
//! //
//! // If your App client does not have a client secret, you can omit this parameter.
//! //
//! // https://docs.aws.amazon.com/cognito/latest/developerguide/signing-up-users-in-your-app.html#cognito-user-pools-computing-secret-hash
//! let client_secret = Some("");
//!
//! let user = User::new(
//!      // The ID of the AWS Cognito User Pool the user is registered with.
//!      "<pool id>",
//!
//!      // The credentials of the user.
//!      "<username>",
//!      "<password>"
//! );
//!
//! let client = SrpClient::<_, ThreadRng>::new(user, client_id, client_secret);
//!
//! // Part 1: Generate the auth parameters for the initial `InitiateAuth` request
//! let AuthParameters {
//!     a, // SRP_A
//!     username, // USERNAME
//!     secret_hash, // SECRET_HASH (if required)
//!     device_key // DEVICE_KEY
//! } = client.get_auth_parameters();
//!
//! // Part 2: Generate the challenge response parameters for the `PASSWORD_VERIFIER` challenge issued
//! // by Cognito in response to the `InitiateAuth` request.
//! let VerificationParameters {
//!     password_claim_secret_block, // PASSWORD_CLAIM_SECRET_BLOCK
//!     password_claim_signature, // PASSWORD_CLAIM_SIGNATURE
//!     secret_hash, // SECRET_HASH (if required)
//!     timestamp // TIMESTAMP
//! } = client.verify(
//!     "SECRET_BLOCK_FROM_INITIATE_AUTH_RESPONSE",
//!     "USER_ID_FOR_SRP_FROM_INITIATE_AUTH_RESPONSE",
//!     "SALT_FROM_INITIATE_AUTH_RESPONSE",
//!     "SRP_B_FROM_INITIATE_AUTH_RESPONSE"
//! )?;
//!
//! # Ok::<(), SrpError>(())
//! ```
//!
//! ### Device authentication
//!
//! The [authentication flow](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow-methods.html#Built-in-authentication-flow-and-challenges)
//! is described in detail the AWS Cognito documentation.
//!
//! When performing the SRP authentication flow, if a `DEVICE_KEY` is provided, AWS Cognito will prompt for device authentication.
//!
//! The correct SRP parameters can be generated for the two [RespondToAuthChallenge](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html) requests needed when the `DEVICE_SRP_AUTH` and
//! `DEVICE_PASSWORD_VERIFIER` challenges are issued.
//!
//! ```no_run
//! use rand::rngs::ThreadRng;
//! use aws_cognito_srp::{AuthParameters, TrackedDevice, SrpClient, SrpError, User, VerificationParameters};
//!
//! let client_id = "";
//!
//! // Optional: If your App client is configured with a client secret, AWS Cognito will require that
//! // a secret is provided during the authentication flow (which requires the client secret).
//! //
//! // If your App client does not have a client secret, you can omit this parameter.
//! //
//! // https://docs.aws.amazon.com/cognito/latest/developerguide/signing-up-users-in-your-app.html#cognito-user-pools-computing-secret-hash
//! let client_secret = Some("");
//!
//! let tracked_device = TrackedDevice::new(
//!      // The ID of the AWS Cognito User Pool the user is registered with.
//!      "<pool id>",
//!
//!      // The username of the user which the device is tracked with.
//!      "<username>",
//!
//!      // The tracked device.
//!      "<device group key>",
//!      "<device key>",
//!      "<device password>"
//! );
//!
//! let client = SrpClient::<_, ThreadRng>::new(tracked_device, client_id, client_secret);
//!
//! // Part 1: Generate the challenge response parameters for the `RespondToAuthChallenge` request
//! // when responding to the `DeviceSrpAuth` challenge issued by AWS Cognito.
//! let AuthParameters {
//!     a, // SRP_A
//!     username, // USERNAME
//!     secret_hash, // SECRET_HASH (if required)
//!     device_key // DEVICE_KEY
//! } = client.get_auth_parameters();
//!
//! // Part 2: Generate the challenge response parameters for the `DEVICE_PASSWORD_VERIFIER` challenge
//! // issued by AWS Cognito in response to the `RespondToAuthChallenge` request.
//! let VerificationParameters {
//!     password_claim_secret_block, // PASSWORD_CLAIM_SECRET_BLOCK
//!     password_claim_signature, // PASSWORD_CLAIM_SIGNATURE
//!     secret_hash, // SECRET_HASH (if required)
//!     timestamp // TIMESTAMP
//! } = client.verify(
//!     "SECRET_BLOCK_FROM_INITIATE_AUTH_RESPONSE",
//!     "USER_ID_FOR_SRP_FROM_INITIATE_AUTH_RESPONSE",
//!     "SALT_FROM_INITIATE_AUTH_RESPONSE",
//!     "SRP_B_FROM_INITIATE_AUTH_RESPONSE"
//! )?;
//!
//! # Ok::<(), SrpError>(())
//! ```
//!
//! ### Confirm device
//!
//! Once a user has been authenticated, if the User Pool is configured to allow device tracking, a
//! [ConfirmDevice](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmDevice.html) request can be made.
//!
//! This request passes in a verifier and salt for a random password generated for the untracked device. And, once confirmed, subsequent logins can use
//! [device authentication flow](#device-authentication), citing the device key, along with the random password generated here.
//!
//! ```no_run
//! use rand::rngs::ThreadRng;
//! use aws_cognito_srp::{TrackedDevice, PasswordVerifierParameters, SrpClient, SrpError, User, UntrackedDevice};
//!
//! let client_id = "";
//!
//! // Optional: If your App client is configured with a client secret, AWS Cognito will require that
//! // a secret is provided during the authentication flow (which requires the client secret).
//! //
//! // If your App client does not have a client secret, you can omit this parameter.
//! //
//! // https://docs.aws.amazon.com/cognito/latest/developerguide/signing-up-users-in-your-app.html#cognito-user-pools-computing-secret-hash
//! let client_secret = Some("");
//!
//! let untracked_device = UntrackedDevice::new(
//!      // The ID of the AWS Cognito User Pool the user is registered with.
//!      "<pool id>",
//!
//!      // The device to be tracked.
//!      "<device group key>",
//!      "<device key>"
//! );
//!
//! let client = SrpClient::<_, ThreadRng>::new(untracked_device, client_id, client_secret);
//!
//! // Generate a new password, and the verifier parameters (verifier and salt) for the `ConfirmDevice`
//! // request.
//! let PasswordVerifierParameters {
//!     verifier, // PasswordVerifier
//!     salt, // Salt
//!     password // The devices password (should be stored to use with device authentication later)
//! } = client.get_password_verifier();
//!
//! // The untracked device can then be converted into a tracked device, which can be used for Device
//! // authentication, after the `ConfirmDevice` request has succeeded.
//!
//! # Ok::<(), SrpError>(())
//! ```
//!
//! ## Contributing
//!
//! Many of the tests require that an AWS Cognito User Pool, configured with SRP authentication and device
//! tracking, be available to act as a mock server.
//!
//! The setup of a suitable User Pool is fully automated with Terraform (see the [`infrastructure`](infrastructure/) folder).
//!
//! ### Set up
//!
//! In order to setup the test environment, Terraform needs to be installed and AWS credentials need to be
//! configured locally.
//!
//! Once this is done, running `apply` should setup the Terraform backend, and the user pool and app client in the correct state:
//! ```sh
//! # Setup state backend
//! cd infrastructure/state && terraform init && terraform apply
//!
//! # Setup user pool
//! cd infrastructure/tests && terraform init --backend-config="./local.config" && terraform apply
//! ```
//!
//! After the user pool is set up, multiple environment variables need to be set in a `.env` file.
//!
//! The `.env` file can be created by using `.env.example` as a template:
//! ```sh
//! cp .env.example .env
//! ```
//!
//! ### Running tests
//!
//! The tests can be run with:
//! ```sh
//! cargo test
//! ```
//!
//! ### Tear down
//!
//! The test environment can be torn down at any point with:
//! ```sh
//! cd infrastructure/tests && terraform destroy
//! ```

#[macro_use]
extern crate lazy_static;

pub use crate::client::{AuthParameters, PasswordVerifierParameters, VerificationParameters};
pub use crate::client::{Credentials, SrpClient, TrackedDevice, UntrackedDevice, User};
pub use crate::error::SrpError;

mod client;
mod constant;
mod error;
