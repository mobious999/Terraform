provider "aws" {
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

resource "aws_guardduty_detector" "GuardDuty" {
  enable = true
}

Terraform support not available at this time



resource "aws_cloudwatch_event_rule" "CwEvent1" {
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

resource "aws_config_config_rule" "ConfigRule1" {
  name = "guardduty-enabled-centralized"
  description = "A Config rule that checks whether Amazon GuardDuty is enabled in your AWS account and region. If you provide an AWS account for centralization, the rule evaluates the Amazon GuardDuty results in the centralized account. The rule is compliant when Amazo..."

  source {
    owner = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }
  scope {
    compliance_resource_types = []
  }
}



resource "aws_config_config_rule" "ConfigRule2" {
  name = "guardduty_untreated_findings"
  description = "A config rule that checks whether GuardDuty has untreated findings. The rule is NON_COMPLIANT if the GuardDuty has untreated finding older than X days."
  input_parameters = "{\"daysLowSev\":\"30\",\"daysMediumSev\":\"7\",\"daysHighSev\":\"1\"}"
  depends_on = [ aws_lambda_permission.LambdaPermissionConfigRule2 ]

  scope {
    compliance_resource_types = ["AWS::::Account"]
  }
  source {
    owner = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.LambdaFunctionConfigRule2.arn
    source_detail {
      event_source = "aws.config"
      message_type = "ScheduledNotification"
      maximum_execution_frequency = "TwentyFour_Hours"
    }
  }
}

resource "aws_lambda_function" "LambdaFunctionConfigRule2" {
  function_name = "LambdaFunctionForguardduty_untreated_findings"
  timeout = "300"
  runtime = "python3.6"
  handler = "index.lambda_handler"
  role = aws_iam_role.LambdaIamRoleConfigRule2.arn
  s3_bucket = "asecure-cloud-cf-aux-${data.aws_region.current.name}"
  s3_key = "GUARDDUTY_UNTREATED_FINDINGS.zip"
}

resource "aws_lambda_permission" "LambdaPermissionConfigRule2" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.LambdaFunctionConfigRule2.function_name
  principal = "config.amazonaws.com"
}

resource "aws_iam_role" "LambdaIamRoleConfigRule2" {
  name = "IamRoleForguardduty_untreated_findings"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["lambda.amazonaws.com"]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule2ManagedPolicyRoleAttachment0" {
  role = aws_iam_role.LambdaIamRoleConfigRule2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule2ManagedPolicyRoleAttachment1" {
  role = aws_iam_role.LambdaIamRoleConfigRule2.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRulesExecutionRole"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule2ManagedPolicyRoleAttachment2" {
  role = aws_iam_role.LambdaIamRoleConfigRule2.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
