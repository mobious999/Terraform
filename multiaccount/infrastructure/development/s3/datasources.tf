provider "aws" {
  region  = "${var.region}"
  profile = "${var.profile}"
  version = "~> 2.0"
}

terraform {
  backend "s3" {
    encrypt = true
    bucket  = "${var.environment}-terraform-state"
    profile = "${var.profile}"
    key     = "${var.environment}/s3.tfstate"
    region  = "${var.region}"
  }
}

data "terraform_remote_state" "s3" {
 backend     = "s3"
 config {
  bucket  = "${var.environment}-terraform-state"
  profile = "${var.profile}"
  key     = "${var.statebucketname}/s3.tfstate"
  region  = "${var.region}"
 }
}

data "terraform_remote_state" "backup" {
 backend     = "s3"
 config {
  bucket  = "${var.environment}-terraform-state"
  profile = "${var.profile}"
  key     = "${var.statebucketname}/backup.tfstate"
  region  = "${var.region}"
 }
}

data "terraform_remote_state" "cloudwatch" {
 backend     = "s3"
 config {
  bucket  = "${var.environment}-terraform-state"
  profile = "${var.profile}"
  key     = "${var.statebucketname}/cloudwatch.tstate"
  region  = "${var.region}"
 }
}

data "terraform_remote_state" "config" {
 backend     = "s3"
 config {
  bucket  = "${var.environment}-terraform-state"
  profile = "${var.profile}"
  key     = "${var.statebucketname}/config.tfstate"
  region  = "${var.region}"
 }
}

data "terraform_remote_state" "iam_policies" {
 backend     = "s3"
 config {
  bucket  = "${var.environment}-terraform-state"
  profile = "${var.profile}"
  key     = "${var.statebucketname}/iam_policies.tfstate"
  region  = "${var.region}"
 }
}

data "terraform_remote_state" "iam_roles" {
 backend     = "s3"
 config {
  bucket  = "${var.environment}-terraform-state"
  profile = "${var.profile}"
  key     = "${var.statebucketname}/iam_roles.tfstate"
  region  = "${var.region}"
 }
}

data "terraform_remote_state" "iam_users" {
 backend     = "s3"
 config {
  bucket  = "${var.environment}-terraform-state"
  profile = "${var.profile}"
  key     = "${var.statebucketname}/iam_roles.tfstate"
  region  = "${var.region}"
 }
}

data "terraform_remote_state" "ecs" {
 backend     = "s3"
 config {
  bucket  = "${var.environment}-terraform-state"
  profile = "${var.profile}"
  key     = "${var.statebucketname}/ecs.tfstate"
  region  = "${var.region}"
 }
}

data "terraform_remote_state" "eks" {
 backend     = "s3"
 config {
  bucket  = "${var.environment}-terraform-state"
  profile = "${var.profile}"
  key     = "${var.statebucketname}/eks.tfstate"
  region  = "${var.region}"
 }
}

data "terraform_remote_state" "ecr" {
 backend     = "s3"
 config {
  bucket  = "${var.environment}-terraform-state"
  profile = "${var.profile}"
  key     = "${var.statebucketname}/ecr.tfstate"
  region  = "${var.region}"
 }
}

data "terraform_remote_state" "batch" {
 backend     = "s3"
 config {
  bucket  = "${var.environment}-terraform-state"
  profile = "${var.profile}"
  key     = "${var.statebucketname}/batch.tfstate"
  region  = "${var.region}"
 }
}







