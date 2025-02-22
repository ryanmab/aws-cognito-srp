resource "aws_cognito_user_pool" "user_pool" {
  name                = format("aws-cognito-srp-ephemeral-user-pool-%s", formatdate("DD-MMM-YYYY-hh-mm-ss", timestamp()))
  deletion_protection = "INACTIVE"

  username_configuration {
    case_sensitive = false
  }

  device_configuration {
    challenge_required_on_new_device      = false
    device_only_remembered_on_user_prompt = false
  }

  lifecycle {
    ignore_changes = [
      password_policy,
      schema
    ]
  }
}

resource "aws_cognito_user" "test_user" {
  user_pool_id = aws_cognito_user_pool.user_pool.id
  username     = var.integration_test_user_email
  password     = var.integration_test_user_password

  enabled = true

  attributes = {
    email          = var.integration_test_user_email
    email_verified = true
  }
}

resource "aws_cognito_user_pool_client" "test_client" {
  user_pool_id = aws_cognito_user_pool.user_pool.id
  name         = "integration-test-client"

  explicit_auth_flows = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  generate_secret     = true
}