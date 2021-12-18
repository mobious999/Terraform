resource "aws_iam_role" "config_remediation_role" {
  name = "config_remediation_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ssm.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_policy" "allow_remediation" {
  name        = "allow_remediation"
  description = "Policy to allow posting remediate config rules"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "sns:Publish"
      ],
      "Effect": "Allow",
      "Resource": "${aws_sns_topic.config_topic.arn}"
    },
    {
      "Action": [
        "ec2:ReleaseAddress",
        "s3:Get*",
        "s3:List*",
        "s3:Put*",
        "s3:Update*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "attach_remediation_policy" {
  role       = aws_iam_role.config_remediation_role.name
  policy_arn = aws_iam_policy.allow_remediation.arn
}
