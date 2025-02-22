terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  required_version = ">= 1.2.0"

  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
}

module "cognito" {
  source                         = "./cognito"
  integration_test_user_email    = var.integration_test_user_email
  integration_test_user_password = var.integration_test_user_password
}