provider "aws" {
  region  = var.region
  profile = var.profile
  version = "~> 2.0"
}

terraform {
  backend "s3" {
    bucket  = "medpro-terraform-state"
    profile = "medpro-sharedservices-role"
    key     = "wfl-eis-dev/iam-roles.tfstate"
    region  = "us-east-2"
  }
}

######################## Okta SAML IdP ########################################### 
resource "aws_iam_saml_provider" "okta" {
  name                   = "Okta"
  saml_metadata_document = ""
  lifecycle {
    ignore_changes = [saml_metadata_document]
  }
}


######################## IAM role for Full Admin #################################
data "aws_iam_policy_document" "AssumeRoleWithSAMLPolicy" {
  statement {
    actions = ["sts:AssumeRoleWithSAML"]
    condition {
      test     = "StringEquals"
      variable = "SAML:aud"

      values = ["https://signin.aws.amazon.com/saml"]
    }

    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::709546977758:saml-provider/Okta"]
    }
  }
}


resource "aws_iam_role" "FullAdmin" {
  name                 = "AWS-EISDev-Admin"
  assume_role_policy   = data.aws_iam_policy_document.AssumeRoleWithSAMLPolicy.json
  description          = "Allow full admin access. SAML role to be assumed via SSO."
  max_session_duration = 14400 # 4 hours in seconds
  tags = merge(
    map("Name", "AWS-EISDev-Admin"),
    var.tags
  )
}

resource "aws_iam_role_policy_attachment" "FullAdmin_attach" {
  role       = aws_iam_role.FullAdmin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy_attachment" "support_admin_attach" {
  role       = aws_iam_role.FullAdmin.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}

######################## IAM role for Read Only ##################################

resource "aws_iam_role" "ReadOnly" {
  name               = "AWS-EISDev-ReadOnly"
  assume_role_policy = data.aws_iam_policy_document.AssumeRoleWithSAMLPolicy.json
  description        = "Allow Read Only access. SAML role to be assumed via SSO."
  tags = merge(
    map("Name", "AWS-EISDev-ReadOnly"),
    var.tags
  )
}

resource "aws_iam_role_policy_attachment" "ReadOnly_attach" {
  role       = aws_iam_role.ReadOnly.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}


data "local_file" "read_only_dev" {
  filename = "${path.module}/readonly-assume-role-policy.json"
}

resource "aws_iam_policy" "read_only_assume_role" {
  name   = "EISDev-ReadOnly-Assume-Sts-Policy"
  policy = data.local_file.read_only_dev.content
}

resource "aws_iam_role_policy_attachment" "read_only_assume" {
  role       = aws_iam_role.ReadOnly.name
  policy_arn = aws_iam_policy.read_only_assume_role.arn
}



# ################### IAM role for User Access ###############################
resource "aws_iam_role" "User" {
  name                 = "AWS-EISDev-User"
  assume_role_policy   = data.aws_iam_policy_document.AssumeRoleWithSAMLPolicy.json
  description          = "Allow Business User access. SAML role to be assumed via SSO."
  max_session_duration = 14400 # 4 hours in seconds
  tags = merge(
    map("Name", "AWS-EISDev-User"),
    var.tags
  )
}

resource "aws_iam_role_policy_attachment" "User_attach" {
  role       = aws_iam_role.User.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}



# ################### IAM role for Billing Access ###############################
resource "aws_iam_role" "Billing" {
  name               = "AWS-EISDev-Billing"
  assume_role_policy = data.aws_iam_policy_document.AssumeRoleWithSAMLPolicy.json
  description        = "Allow Billing User access. SAML role to be assumed via SSO."
  tags = merge(
    map("Name", "AWS-EISDev-Billing"),
    var.tags
  )
}

resource "aws_iam_role_policy_attachment" "Billing_attach" {
  role       = aws_iam_role.Billing.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/Billing"
}

# ################### IAM role for Config S3 Enforcement via Lambda###############################
data "aws_iam_policy_document" "AssumeRoleForLambda" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      identifiers = ["lambda.amazonaws.com"]
      type        = "Service"
    }
  }
}

resource "aws_iam_role" "LambdaS3Config" {
  name               = "AWS-Lambda-S3-Config-Enforcement"
  assume_role_policy = data.aws_iam_policy_document.AssumeRoleForLambda.json
  description        = "Allow Lambda to read SNS, manage S3, and have basic execution access"
  tags = merge(
    map("Name", "AWS-Lambda-S3-Config-Enforcement"),
    var.tags
  )
}

data "local_file" "LambdaPolicyJSON" {
  filename = "${path.module}/lambda-policy.json"
}

resource "aws_iam_role_policy" "LambdaS3ConfigPolicy" {
  name = "AWS-Lambda-S3-Config-Enforcement-Policy"
  role = aws_iam_role.LambdaS3Config.id

  policy = data.local_file.LambdaPolicyJSON.content
}

resource "aws_iam_user" "dev_secrets_user" {
  name = "dev-secrets-mgr"
  tags = merge(var.tags)
}

resource "aws_iam_user_policy" "secrets_manager_read_policy" {
  name   = "SecretsManagerRead"
  user   = aws_iam_user.dev_secrets_user.name
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "secretsmanager:DescribeSecret",
        "secretsmanager:Get*",
        "secretsmanager:List*"
      ],
      "Effect": "Allow",
      "Resource": "*",
      "Condition": {
        "ForAnyValue:IpAddress": {
          "aws:SourceIp": [
            "69.160.218.2/32",
            "69.160.218.66/32",
            "184.18.66.234/32",
            "73.215.63.141/32"
          ]
        }
      }
    }
  ]
}
EOF
}

###okta cross account

resource "aws_iam_role" "okta_cross_account" {
  name = "Okta-Idp-cross-account-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::529996378260:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {}
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "IAMReadOnly_attach" {
  role       = aws_iam_role.okta_cross_account.name
  policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
}
