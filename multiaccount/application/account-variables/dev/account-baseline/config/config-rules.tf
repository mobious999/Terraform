########################## AWS Managed Config Rules #################
resource "aws_config_config_rule" "APPROVED_AMIS_BY_TAG" {
  name = "approved-amis-by-tag"

  source {
    owner             = "AWS"
    source_identifier = "APPROVED_AMIS_BY_TAG"
  }

  depends_on = [aws_config_configuration_recorder.main]

  input_parameters = <<EOF
  {
    "amisByTagKeyAndValue": "Expiration Date,Owner,CostCenter,Name"
  }
  EOF
}

resource "aws_config_config_rule" "INSTANCES_IN_VPC" {
  name        = "ec2-instances-in-vpc"
  description = "Checks whether your EC2 instances belong to a virtual private cloud (VPC). Optionally, you can specify the VPC ID to associate with your instances."

  input_parameters = jsonencode({})

  source {
    owner             = "AWS"
    source_identifier = "INSTANCES_IN_VPC"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_remediation_configuration" "ec2_in_vpc_remediation" {
  config_rule_name = aws_config_config_rule.INSTANCES_IN_VPC.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-PublishSNSNotification"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name         = "Message"
    static_value = "Resource found noncompliant for ${aws_config_config_rule.INSTANCES_IN_VPC.name} rule in ${var.account_name}"
  }
  parameter {
    name         = "TopicArn"
    static_value = aws_sns_topic.config_topic.arn
  }
}

resource "aws_config_config_rule" "EIP_ATTACHED" {
  name = "eip-attached"

  source {
    owner             = "AWS"
    source_identifier = "EIP_ATTACHED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_remediation_configuration" "eip_attached_remediation" {
  config_rule_name = aws_config_config_rule.EIP_ATTACHED.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-ReleaseElasticIP"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name           = "AllocationId"
    resource_value = "RESOURCE_ID"
  }
}

resource "aws_config_config_rule" "ENCRYPTED_VOLUMES" {
  name = "encrypted-ebs-volumes"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder.main]
}


resource "aws_config_config_rule" "INCOMING_SSH_DISABLED" {
  name = "restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_remediation_configuration" "restrict_ssh_remediation" {
  config_rule_name = aws_config_config_rule.INCOMING_SSH_DISABLED.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-PublishSNSNotification"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name         = "Message"
    static_value = "Resource found noncompliant for ${aws_config_config_rule.INCOMING_SSH_DISABLED.name} rule in ${var.account_name}"
  }
  parameter {
    name         = "TopicArn"
    static_value = aws_sns_topic.config_topic.arn
  }
}

resource "aws_config_config_rule" "db-instance-backup-enabled" {
  name        = "db-instance-backup-enabled"
  description = "Checks whether RDS DB instances have backups enabled. Optionally, the rule checks the backup retention period and the backup window."

  input_parameters = jsonencode({})

  source {
    owner             = "AWS"
    source_identifier = "DB_INSTANCE_BACKUP_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_remediation_configuration" "db_backup_remediation" {
  config_rule_name = aws_config_config_rule.db-instance-backup-enabled.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-PublishSNSNotification"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name         = "Message"
    static_value = "Resource found noncompliant for ${aws_config_config_rule.db-instance-backup-enabled.name} rule in ${var.account_name}"
  }
  parameter {
    name         = "TopicArn"
    static_value = aws_sns_topic.config_topic.arn
  }
}

resource "aws_config_config_rule" "rds-instance-public-access-check" {
  name = "rds-instance-public-access-check"

  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_remediation_configuration" "rds_public_remediation" {
  config_rule_name = aws_config_config_rule.rds-instance-public-access-check.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-PublishSNSNotification"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name         = "Message"
    static_value = "Resource found noncompliant for ${aws_config_config_rule.rds-instance-public-access-check.name} rule in ${var.account_name}"
  }
  parameter {
    name         = "TopicArn"
    static_value = aws_sns_topic.config_topic.arn
  }
}

resource "aws_config_config_rule" "cloudtrail-enabled" {
  name = "cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_remediation_configuration" "cloudtrail_remediation" {
  config_rule_name = aws_config_config_rule.cloudtrail-enabled.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-EnableCloudTrail"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name         = "S3BucketName"
    static_value = var.cloudtrail_name
  }
  parameter {
    name         = "TrailName"
    static_value = var.cloudtrail_name
  }
}

resource "aws_config_config_rule" "cloud-trail-cloud-watch-logs-enabled" {
  name = "cloud-trail-cloud-watch-logs-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_remediation_configuration" "cloud-trail-cloud-watch-logs-enabled" {
  config_rule_name = aws_config_config_rule.cloud-trail-cloud-watch-logs-enabled.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-PublishSNSNotification"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name         = "Message"
    static_value = "Resource found noncompliant for ${aws_config_config_rule.cloud-trail-cloud-watch-logs-enabled.name} rule in ${var.account_name}"
  }
  parameter {
    name         = "TopicArn"
    static_value = aws_sns_topic.config_topic.arn
  }
}

resource "aws_config_config_rule" "required-tags" {
  name            = "required-tags"
  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }
  
  scope { 
    compliance_resource_types= ["AWS::ACM::Certificate", "AWS::AutoScaling::AutoScalingGroup", "AWS::CloudFormation::Stack", "AWS::CodeBuild::Project", "AWS::DynamoDB::Table", "AWS::EC2::CustomerGateway", "AWS::EC2::Instance", "AWS::EC2::InternetGateway", "AWS::EC2::NetworkAcl", "AWS::EC2::NetworkInterface", "AWS::EC2::RouteTable", "AWS::EC2::SecurityGroup", "AWS::EC2::Subnet", "AWS::EC2::Volume", "AWS::EC2::VPC", "AWS::EC2::VPNConnection", "AWS::EC2::VPNGateway", "AWS::ElasticLoadBalancing::LoadBalancer", "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::RDS::DBInstance", "AWS::RDS::DBSecurityGroup", "AWS::RDS::DBSnapshot", "AWS::RDS::DBSubnetGroup", "AWS::RDS::EventSubscription", "AWS::Redshift::Cluster", "AWS::Redshift::ClusterParameterGroup", "AWS::Redshift::ClusterSecurityGroup", "AWS::Redshift::ClusterSnapshot", "AWS::Redshift::ClusterSubnetGroup", "AWS::S3::Bucket"]
  }
  input_parameters = <<EOF
  {
    "tag1Key": "Application",
    "tag2Key": "BackupRetention",
    "tag3Key": "CostCenter",
    "tag4Key": "DataClassification",
    "tag5Key": "Environment",
    "tag5Value": "DEV,CIT,IT,SIT,QA,UAT,PPRD,TRN,NFT,PROD",
    "tag6Key": "Name"
  }
  EOF
}

resource "aws_config_config_rule" "multi-region-cloud-trail-enabled" {
  name        = "multi-region-cloud-trail-enabled"
  description = "Checks that there is at least one multi-region AWS CloudTrail. The rule is non-compliant if the trails do not match input parameters."
  source {
    owner             = "AWS"
    source_identifier = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
  }
  maximum_execution_frequency = "TwentyFour_Hours"

  input_parameters = <<EOF
  {
    "s3BucketName": "medpro-cloudtrail"
  }
  EOF
}

resource "aws_config_config_rule" "vpc-flow-logs-enabled" {
  name            = "vpc-flow-logs-enabled"
  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }
}

resource "aws_config_remediation_configuration" "vpc_flow_logs_remediation" {
  config_rule_name = aws_config_config_rule.vpc-flow-logs-enabled.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-PublishSNSNotification"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name         = "Message"
    static_value = "Resource found noncompliant for ${aws_config_config_rule.vpc-flow-logs-enabled.name} rule in ${var.account_name}"
  }
  parameter {
    name         = "TopicArn"
    static_value = aws_sns_topic.config_topic.arn
  }
}

resource "aws_config_config_rule" "guardduty-enabled-centralized" {
  name        = "guardduty-enabled-centralized"
  description = "Checks whether Amazon GuardDuty is enabled in your AWS account and region. If you provide an AWS account for centralization, the rule evaluates the GuardDuty results in that account. The rule is compliant when GuardDuty is enabled."

  input_parameters            = jsonencode({})
  maximum_execution_frequency = "TwentyFour_Hours"

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }
}

resource "aws_config_remediation_configuration" "guardduty_enabled_centralized_remediation" {
  config_rule_name = aws_config_config_rule.guardduty-enabled-centralized.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-PublishSNSNotification"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name         = "Message"
    static_value = "Resource found noncompliant for ${aws_config_config_rule.guardduty-enabled-centralized.name} rule in ${var.account_name}"
  }
  parameter {
    name         = "TopicArn"
    static_value = aws_sns_topic.config_topic.arn
  }
}

resource "aws_config_config_rule" "root-account-mfa-enabled" {
  name            = "root-account-mfa-enabled"
  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }
}

resource "aws_config_remediation_configuration" "root_mfa_remediation" {
  config_rule_name = aws_config_config_rule.root-account-mfa-enabled.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-PublishSNSNotification"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name         = "Message"
    static_value = "Resource found noncompliant for ${aws_config_config_rule.root-account-mfa-enabled.name} rule in ${var.account_name}"
  }
  parameter {
    name         = "TopicArn"
    static_value = aws_sns_topic.config_topic.arn
  }
}

resource "aws_config_config_rule" "iam-user-unused-credentials-check" {
  name            = "iam-user-unused-credentials-check"

source {
    owner             = "AWS"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  }
  input_parameters = <<EOF
  {
    "maxCredentialUsageAge": "90"
  }
  EOF
}

resource "aws_config_remediation_configuration" "iam_user_unused_cred_remediation" {
  config_rule_name = aws_config_config_rule.iam-user-unused-credentials-check.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-PublishSNSNotification"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name         = "Message"
    static_value = "Resource found noncompliant for ${aws_config_config_rule.iam-user-unused-credentials-check.name} rule in ${var.account_name}"
  }
  parameter {
    name         = "TopicArn"
    static_value = aws_sns_topic.config_topic.arn
  }
}

resource "aws_config_config_rule" "password-policy" {
  name            = "password-policy"
  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }
}

resource "aws_config_remediation_configuration" "password_policy_remediation" {
  config_rule_name = aws_config_config_rule.password-policy.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-PublishSNSNotification"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name         = "Message"
    static_value = "Resource found noncompliant for ${aws_config_config_rule.password-policy.name} rule in ${var.account_name}"
  }
  parameter {
    name         = "TopicArn"
    static_value = aws_sns_topic.config_topic.arn
  }
}

resource "aws_config_config_rule" "ebs-volume-inuse" {
  name            = "ebs-volumes-inuse"
  source {
    owner             = "AWS"
    source_identifier = "EC2_VOLUME_INUSE_CHECK"
  }
}

resource "aws_config_remediation_configuration" "ebs_volume_inuse_remediation" {
  config_rule_name = aws_config_config_rule.ebs-volume-inuse.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-PublishSNSNotification"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name         = "Message"
    static_value = "Resource found noncompliant for ${aws_config_config_rule.ebs-volume-inuse.name} rule in ${var.account_name}"
  }
  parameter {
    name         = "TopicArn"
    static_value = aws_sns_topic.config_topic.arn
  }
}

resource "aws_config_config_rule" "s3-public-read" {
  name            = "s3-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}

resource "aws_config_remediation_configuration" "s3_public_read_remediation" {
  config_rule_name = aws_config_config_rule.s3-public-read.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-DisableS3BucketPublicReadWrite"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name           = "S3BucketName"
    resource_value = "RESOURCE_ID"
  }
}

resource "aws_config_config_rule" "s3-public-write" {
  name            = "s3-public-write-prohibited"
 source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }
}

resource "aws_config_remediation_configuration" "s3_public_write_remediation" {
  config_rule_name = aws_config_config_rule.s3-public-write.name
  resource_type    = "AWS::S3::Bucket"
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-DisableS3BucketPublicReadWrite"
  target_version   = "1"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.config_remediation_role.arn
  }
  parameter {
    name           = "S3BucketName"
    resource_value = "RESOURCE_ID"
  }
}


