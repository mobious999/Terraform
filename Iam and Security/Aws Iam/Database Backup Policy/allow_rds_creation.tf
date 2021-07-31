provider "aws" {
  region  = "us-east-2"
}

resource "aws_iam_policy" "IamPolicy" {
  name = "allow_rds_creation"
  description = "An IAM policy that allows users to only launch RDS instances of a specific instance type and database engine (Default: t2.micro and mysql)."
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "rds:CreateDBInstance"
      ],
      "Resource": "*",
      "Effect": "Allow",
      "Condition": {
        "StringEquals": {
          "rds:DatabaseEngine": "mysql",
          "rds:DatabaseClass": "db.t2.micro"
        }
      }
    }
  ]
}
POLICY

}