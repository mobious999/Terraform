provider "aws" {
  region = "us-east-1"
}

#
# AWS IAM Policies
#

data "aws_iam_policy_document" "users_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::<PRIMARY ACCOUNT ID>:root"]
    }
  }
}

data "aws_iam_policy_document" "child_users_access" {
  statement {
    actions   = ["*"]
    resources = ["*"]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"

      values = [
        "arn:aws:iam::<PRIMARY ACCOUNT ID>:group/child-users",
      ]
    }
  }
}

resource "aws_iam_policy" "child_users_access" {
  name   = "child-users-access"
  policy = "${data.aws_iam_policy_document.child_users_access.json}"
}

resource "aws_iam_policy_attachment" "child_users_access" {
  name       = "child-users-access"
  policy_arn = "${aws_iam_policy.child_users_access.arn}"

  roles = [
    "${aws_iam_role.child_users.id}"
  ]
}

#
# AWS IAM Roles
#

resource "aws_iam_role" "child_users" {
  name               = "users_assume_role_default"
  assume_role_policy = "${data.aws_iam_policy_document.users_assume_role.json}"
}