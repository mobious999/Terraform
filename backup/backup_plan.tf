v0.12+Missing Parametersselect region
provider "aws" {
}

data "aws_caller_identity" "current" {}

resource "aws_backup_plan" "BackupPlan" {
  name = "CustomBackupPlan"
}

