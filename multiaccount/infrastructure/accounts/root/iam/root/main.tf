provider "aws" {
  region = "us-east-1"
}

#
# AWS IAM Policy Resources
#

data "aws_iam_policy_document" "assume_role_child_default" {
  statement {
    actions = ["sts:AssumeRole"]

    resources = [
      "arn:aws:iam::<YOUR CHILD ACCOUNT ID>:role/users_assume_role_default",
    ]
  }
}

resource "aws_iam_policy" "assume_role_child_user" {
  name   = "assume-role-child-user"
  policy = "${data.aws_iam_policy_document.assume_role_child_default.json}"
}

resource "aws_iam_policy_attachment" "assume_role_child_user" {
  name       = "assume-role-child-user"
  policy_arn = "${aws_iam_policy.assume_role_child_user.arn}"

  groups = [
    "${aws_iam_group.child_users.id}",
  ]
}


#
# AWS IAM Users and Groups
#

resource "aws_iam_user" "boaty_mcboatface" {
  name          = "boaty.mcboatface"
  force_destroy = true
}

resource aws_iam_group "child_users" {
  name = "child-users"
}

resource "aws_iam_group_membership" "child_users" {
  name = "child-users"

  users = [
    "${aws_iam_user.boaty_mcboatface.name}",
  ]

  group = "${aws_iam_group.child_users.name}"
}