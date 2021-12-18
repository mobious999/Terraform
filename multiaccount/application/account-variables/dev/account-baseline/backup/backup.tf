resource "aws_backup_plan" "dev_ec2_backup_plan" {
  name = "dev_ec2_backup_plan"

  rule {
    rule_name         = "ec2_backup_rule"
    target_vault_name = aws_backup_vault.ec2_backup_vault.name
    schedule          = "cron(0 5 ? * SAT *)" #### 1am every Saturday ####
    lifecycle {
      delete_after = 14 
    }
  }
}

data "aws_kms_key" "backup_key" { 
  key_id = "alias/aws/backup"
}

resource "aws_backup_vault" "ec2_backup_vault" {
  name        = "ec2_backup_vault"
  kms_key_arn = data.aws_kms_key.backup_key.arn 
}

resource "aws_iam_role" "allow_backups_role" {
  name               = "allow_backups_role"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": ["sts:AssumeRole"],
      "Effect": "allow",
      "Principal": {
        "Service": ["backup.amazonaws.com"]
      }
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "allow_backups" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
  role       = aws_iam_role.allow_backups_role.name
}

data "aws_instances" "all_instances" {
  filter {
    name = "instance-state-name"
    values = ["running"]
  }
}

resource "aws_backup_selection" "backup_selection" {
  iam_role_arn = aws_iam_role.allow_backups_role.arn
  name         = "backup_selection"
  plan_id      = aws_backup_plan.dev_ec2_backup_plan.id
  resources    = formatlist("arn:aws:ec2:${var.region}:${var.account_map["wellfleet-eis-dev"]}:instance/%s", data.aws_instances.all_instances.ids)
}

####### UNSURE IF VAULT POLICY NECESSARY ##########

# resource "aws_backup_vault_policy" "vault_policy" {
#   backup_vault_name = aws_backup_vault.ec2_backup_vault.name

#   policy = <<POLICY
# {
#   "Version": "2012-10-17",
#   "Id": "default",
#   "Statement": [
#     {
#       "Sid": "default",
#       "Effect": "Allow",
#       "Principal": {
#         "AWS": "*"
#       },
#       "Action": [
#         "backup:DescribeBackupVault",
#         "backup:DeleteBackupVault",
#         "backup:PutBackupVaultAccessPolicy",
#         "backup:DeleteBackupVaultAccessPolicy",
#         "backup:GetBackupVaultAccessPolicy",
#         "backup:StartBackupJob",
#         "backup:GetBackupVaultNotifications",
#         "backup:PutBackupVaultNotifications"
#       ],
#       "Resource": "${aws_backup_vault.ec2_backup_vault.arn}"
#     }
#   ]
# }
# POLICY
# }