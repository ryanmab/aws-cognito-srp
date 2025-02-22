variable "aws_region" {
  type    = string
  default = "eu-west-2"
}

variable "integration_test_user_email" {
  type      = string
  sensitive = true
}

variable "integration_test_user_password" {
  type      = string
  sensitive = true
}