provider "aws" {
}

resource "aws_iam_role" "IamRoleForAwsBackup" {
  name = "IamRoleForAwsBackup"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["backup.amazonaws.com"]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "IamRoleForAwsBackupManagedPolicyRoleAttachment0" {
  role = aws_iam_role.IamRoleForAwsBackup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "IamRoleForAwsBackupManagedPolicyRoleAttachment1" {
  role = aws_iam_role.IamRoleForAwsBackup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}



resource "aws_backup_plan" "BackupPlan" {
  name = "CustomBackupPlan"
}

