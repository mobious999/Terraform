provider "aws" {
  region  = "us-east-2"
}

resource "aws_config_config_rule" "ConfigRule" {
  name = "ebs-in-backup-plan"
  description = "A Config rule that checks if Amazon Elastic Block Store (Amazon EBS) volumes are added in backup plans of AWS Backup. The rule is NON_COMPLIANT if Amazon EBS volumes are not included in backup plans."

  source {
    owner = "AWS"
    source_identifier = "EBS_IN_BACKUP_PLAN"
  }
  scope {
    compliance_resource_types = []
  }
}