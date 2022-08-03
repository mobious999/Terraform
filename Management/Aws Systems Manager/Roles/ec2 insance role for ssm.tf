provider "aws" {
  region  = "us-east-2"
}

resource "aws_iam_role" "IamRole" {
  name = "Ec2RoleForSSM"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["ec2.amazonaws.com"]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_instance_profile" "ec2InstanceProfile" {
  role = aws_iam_role.IamRole.name
  name = "Ec2RoleForSSM"
}
resource "aws_iam_role_policy_attachment" "IamRoleManagedPolicyRoleAttachment0" {
  role = aws_iam_role.IamRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "IamRoleManagedPolicyRoleAttachment1" {
  role = aws_iam_role.IamRole.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "IamRoleManagedPolicyRoleAttachment2" {
  role = aws_iam_role.IamRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMDirectoryServiceAccess"
}

resource "aws_iam_role_policy" "IamRoleInlinePolicyRoleAttachment0" {
  name = "AllowAccessToS3"
  role = aws_iam_role.IamRole.id
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:PutObjectAcl"
            ],
            "Resource": "arn:aws:s3:::*/*"
        }
    ]
}
POLICY
}

resource "aws_iam_role_policy" "IamRoleInlinePolicyRoleAttachment1" {
  name = "AllowAccessToVpcEndpoints"
  role = aws_iam_role.IamRole.id
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::aws-ssm-us-east-2/*",
                "arn:aws:s3:::aws-windows-downloads-us-east-2/*",
                "arn:aws:s3:::amazon-ssm-us-east-2/*",
                "arn:aws:s3:::amazon-ssm-packages-us-east-2/*",
                "arn:aws:s3:::us-east-2-birdwatcher-prod/*",
                "arn:aws:s3:::patch-baseline-snapshot-us-east-2/*"
            ]
        }
    ]
}
POLICY
}
