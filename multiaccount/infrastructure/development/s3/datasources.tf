provider "aws" {
  region  = "${var.region}"
  profile = "${var.profile}"
  version = "~> 2.0"
}

terraform {
  backend "s3" {
    bucket  = "${var.environment}-terraform-state"
    profile = "${var.profile}"
    key     = "development/s3.tfstate"
    region  = "us-east-2"
  }
}

data "terraform_remote_state" "network" {
  backend = "s3"
  config = {
    bucket  = "${var.environment}-terraform-state"
    profile = "${var.profile}"
    key     = "${var.environment}/network.tfstate"
    region  = "${var.region}"
  }
}

data "terraform_remote_state" "vpc" {
  backend = "s3"
  config = {
    bucket  = "${var.environment}-terraform-state"
    profile = "${var.profile}"
    key     = "${var.environment}/vpc.tfstate"
    region  = "${var.region}"
  }
}

data "terraform_remote_state" "iam" {
  backend = "s3"
  config = {
    bucket  = "${var.environment}-terraform-state"
    profile = "${var.profile}"
    key     = "${var.environment}/iam.tfstate"
    region  = "${var.region}"
  }
}

data "terraform_remote_state" "iam_roles" {
  backend = "s3"
  config = {
    bucket  = "${var.environment}-terraform-state"
    profile = "${var.profile}"
    key     = "${var.environment}/iam_roles.tfstate"
    region  = "${var.region}"
  }
}
