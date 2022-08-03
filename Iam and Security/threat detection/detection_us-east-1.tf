provider "aws" {
  region  = "us-east-1"
}

data "aws_caller_identity" "current" {}

resource "aws_guardduty_detector" "GuardDuty" {
  enable = true
}

resource "aws_inspector_assessment_template" "AssessmentTemplate" {
  name = "Inspector Assessment Template_QaW"
  duration = 3600
  rules_package_arns = ["arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gEjTy7T7"]
  target_arn = aws_inspector_assessment_target.AssessmentTargetForAssessmentTemplate.arn
}

resource "aws_inspector_assessment_target" "AssessmentTargetForAssessmentTemplate" {
  name = "Amazon Inspector Targets"
}



resource "aws_iam_role" "IamRoleForAssessmentTemplate" {
  name = "IamRoleForInspectorScheduledEventlRn"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["events.amazonaws.com"]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "IamRoleForAssessmentTemplateInlinePolicyRoleAttachment0" {
  name = "InspectorAssessmentTrigger"
  role = aws_iam_role.IamRoleForAssessmentTemplate.id
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "inspector:StartAssessmentRun"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
}



resource "aws_cloudwatch_event_rule" "CwEventForAssessmentTemplate" {
  name = "InspectorScheduledAssessmentdkW"
  description = "Scheduled trigger for Amazon Inspector Assessment: "
  schedule_expression = "cron(00 00 ? * SAT *)"
}

resource "aws_cloudwatch_event_target" "TargetForCwEventForAssessmentTemplate" {
  rule = aws_cloudwatch_event_rule.CwEventForAssessmentTemplate.name
  target_id = "AmazonInspectorAssessment"
  arn = aws_inspector_assessment_template.AssessmentTemplate.arn
  role_arn = aws_iam_role.IamRoleForAssessmentTemplate.arn
}

resource "aws_securityhub_account" "SecurityHub" {
}



Terraform support not available at this time



resource "aws_cloudwatch_event_rule" "CwEvent1" {
  name = "detect-securityhub-finding"
  description = "A CloudWatch Event Rule that triggers on AWS Security Hub findings. The Event Rule can be used to trigger notifications or remediative actions using AWS Lambda."
  is_enabled = true
  event_pattern = <<PATTERN
{
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "source": [
    "aws.securityhub"
  ]
}
PATTERN

}

resource "aws_cloudwatch_event_target" "TargetForCwEvent1" {
  rule = aws_cloudwatch_event_rule.CwEvent1.name
  target_id = "target-id1"
  arn = module.SnsTopic1.arn
}

data "aws_iam_policy_document" "topic-policy-PolicyForSnsTopic" {
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:GetTopicAttributes",
      "SNS:SetTopicAttributes",
      "SNS:AddPermission",
      "SNS:RemovePermission",
      "SNS:DeleteTopic",
      "SNS:Subscribe",
      "SNS:ListSubscriptionsByTopic",
      "SNS:Publish",
      "SNS:Receive"
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        data.aws_caller_identity.current.account_id
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      module.SnsTopic1.arn
    ]

    sid = "__default_statement_ID"
  }
  
  statement {
    actions = [
      "sns:Publish"
    ]

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [
      module.SnsTopic1.arn
    ]

    sid = "TrustCWEToPublishEventsToMyTopic"
  }
}

resource "aws_sns_topic_policy" "TopicPolicyForSnsTopic1" {
  arn = module.SnsTopic1.arn
  policy = data.aws_iam_policy_document.topic-policy-PolicyForSnsTopic.json
}

resource "aws_cloudwatch_event_rule" "CwEvent2" {
  name = "detect-guardduty-finding"
  description = "A CloudWatch Event Rule that triggers on Amazon GuardDuty findings. The Event Rule can be used to trigger notifications or remediative actions using AWS Lambda."
  is_enabled = true
  event_pattern = <<PATTERN
{
  "detail-type": [
    "GuardDuty Finding"
  ],
  "source": [
    "aws.guardduty"
  ]
}
PATTERN

}

resource "aws_cloudwatch_event_target" "TargetForCwEvent2" {
  rule = aws_cloudwatch_event_rule.CwEvent2.name
  target_id = "target-id1"
  arn = module.SnsTopic1.arn
}

resource "aws_config_configuration_recorder" "ConfigurationRecorder" {
  role_arn = aws_iam_role.ConfigIamRole.arn

  recording_group {
    all_supported = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "DeliveryChannel" {
  s3_bucket_name = aws_s3_bucket.S3BucketForConfig.id
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]
}

resource "aws_config_configuration_recorder_status" "ConfigurationRecorderStatus" {
  name = aws_config_configuration_recorder.ConfigurationRecorder.name
  is_enabled = true
  depends_on = [ aws_config_delivery_channel.DeliveryChannel ]
}

resource "aws_s3_bucket" "S3BucketForConfig" {
  bucket = "s3-bucket-random-name-wJRSU"
}



resource "aws_iam_role" "ConfigIamRole" {
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["config.amazonaws.com"]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "ConfigIamRoleManagedPolicyRoleAttachment0" {
  role = aws_iam_role.ConfigIamRole.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}

resource "aws_iam_role_policy" "ConfigIamRoleInlinePolicyRoleAttachment0" {
  name = "allow-access-to-config-s3-bucket"
  role = aws_iam_role.ConfigIamRole.id
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject"
            ],
            "Resource": [
                "arn:aws:s3:::s3-bucket-random-name-wJRSU/*"
            ],
            "Condition": {
                "StringLike": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketAcl"
            ],
            "Resource": "arn:aws:s3:::s3-bucket-random-name-wJRSU"
        }
    ]
}
POLICY
}


