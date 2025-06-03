provider "aws" {
  region = "eu-west-2"
}

resource "aws_s3_bucket" "terraform_state" {
  bucket = "aws-cognito-srp-tf-state"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state_lifecycle" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    id = "delete-old-state-files"

    filter {
      # Only delete state files with the prefix "ci/" - these were created by GitHub workflow runs.
      prefix = "ci/"
    }

    expiration {
      # Delete the current version of state files after 1 day. These should be the state files
      # for old Terraform CI runs which have finished.
      days = 1
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }

    status = "Enabled"
  }

  depends_on = [
    aws_s3_bucket.terraform_state
  ]
}

