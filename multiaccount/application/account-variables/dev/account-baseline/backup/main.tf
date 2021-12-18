provider "aws" {
  region  = var.region
  profile = var.profile
  version = "~> 3.0"
}

terraform {
  backend "s3" {
    bucket  = "medpro-terraform-state"
    profile = "medpro-sharedservices-role"
    key     = "wfl-eis-dev/backup.tfstate"
    region  = "us-east-2"
  }
}

# data "terraform_remote_state" "security-config" {
#   backend = "s3"

#   config = {
#     bucket  = "medpro-terraform-state"
#     profile = "medpro-sharedservices-role"
#     key     = "security/config.tfstate"
#     region  = var.region
#   }
# }

#### Config Recorder #######

# resource "aws_config_configuration_recorder" "main" {
#   name     = "${var.customer_identifier_prefix}-configuration-recorder"
#   role_arn = aws_iam_role.config-role.arn
#   recording_group {
#     all_supported                 = true
#     include_global_resource_types = true
#   }
# }

# resource "aws_config_configuration_recorder_status" "main" {
#   name       = aws_config_configuration_recorder.main.name
#   is_enabled = true
#   depends_on = [aws_config_delivery_channel.medpro-config-delivery-channel]
# }

# resource "aws_config_delivery_channel" "medpro-config-delivery-channel" {
#   name           = "${var.customer_identifier_prefix}-config-delivery-channel"
#   s3_bucket_name = data.terraform_remote_state.security-config.outputs.config_s3_name
#   snapshot_delivery_properties {
#     delivery_frequency = var.config_delivery_frequency
#   }
#   depends_on = [aws_config_configuration_recorder.main]
# }

# ####### SNS ########
# resource "aws_sns_topic" "config_topic" {
#   name = "medpro-${var.account_name}-config-sns"
# }

# ######### IAM ############

# resource "aws_iam_role" "config-role" {
#   name = "MedProConfigServiceRole"

#   assume_role_policy = <<EOF
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Sid": "config",
#       "Effect": "Allow",
#       "Principal": {
#         "Service": "config.amazonaws.com"
#       },
#       "Action": "sts:AssumeRole"
#     }
#   ]
# }
# EOF
# }

# resource "aws_iam_role_policy_attachment" "organization-attach" {
#   role       = aws_iam_role.config-role.name
#   policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
# }

# resource "aws_iam_role_policy_attachment" "config-attach" {
#   role       = aws_iam_role.config-role.name
#   policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
# }
