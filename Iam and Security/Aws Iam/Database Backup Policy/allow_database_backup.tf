provider "aws" {
}

resource "aws_iam_policy" "IamPolicy" {
  name = "Database Backup Policy"
  description = "An IAM policy that allows restoring RDS databases. This policy also provides the permissions necessary to complete this action programmatically and in the console."
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:Describe*",
        "rds:CreateDBParameterGroup",
        "rds:CreateDBSnapshot",
        "rds:DeleteDBSnapshot",
        "rds:Describe*",
        "rds:DownloadDBLogFilePortion",
        "rds:List*",
        "rds:ModifyDBInstance",
        "rds:ModifyDBParameterGroup",
        "rds:ModifyOptionGroup",
        "rds:RebootDBInstance",
        "rds:RestoreDBInstanceFromDBSnapshot",
        "rds:RestoreDBInstanceToPointInTime"
      ],
      "Resource": "*",
      "Effect": "Allow"
    }
  ]
}
POLICY

}