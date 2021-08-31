provider "aws" {
}

resource "aws_s3_bucket" "S3SharedBucket" {
  bucket = "s3-bucket-random-name-yKQpXkvIBSFmYUA"
  acl = "log-delivery-write"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  logging {
    target_bucket = "s3-bucket-random-name-yKQpXkvIBSFmYUA"
    target_prefix = ""
  }
}

resource "aws_s3_bucket_public_access_block" "blockPublicAccess" {
  bucket = aws_s3_bucket.S3SharedBucket.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
  depends_on = [ aws_s3_bucket_policy.BucketPolicy ]
}

data "aws_iam_policy_document" "s3-bucket-policy-forS3SharedBucket" {

  statement {
    actions = ["s3:GetBucketAcl"]
    effect = "Allow"
    resources = [aws_s3_bucket.S3SharedBucket.arn]
    principals {
      type = "Service"
      identifiers = ["cloudtrail.amazonaws.com","config.amazonaws.com"]
    }
  }
  statement {
    actions = ["s3:PutObject"]
    effect = "Allow"
    resources = [join("",["",aws_s3_bucket.S3SharedBucket.arn,"/*"])]
    principals {
      type = "Service"
      identifiers = ["cloudtrail.amazonaws.com","config.amazonaws.com"]
    }
    condition {
      test = "StringEquals"
      variable = "s3:x-amz-acl"
      values = ["bucket-owner-full-control"]
    }
  }
}
resource "aws_s3_bucket_policy" "BucketPolicy" {
  bucket = aws_s3_bucket.S3SharedBucket.id
  policy = data.aws_iam_policy_document.s3-bucket-policy-forS3SharedBucket.json
}

resource "aws_cloudtrail" "CloudTrail" {
  name = "ManagementEventsTrail"
  s3_bucket_name = aws_s3_bucket.S3SharedBucket.id
  is_multi_region_trail = true
  enable_log_file_validation = true
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.CWLogGroupForCloudTrail.arn}:*"
  cloud_watch_logs_role_arn = aws_iam_role.CwLogIamRole.arn
  depends_on = [ aws_s3_bucket_policy.BucketPolicy ]

  event_selector {
    include_management_events = true
    read_write_type = "All"
  }
}

resource "aws_iam_role" "CwLogIamRole" {
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["cloudtrail.amazonaws.com"]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "CwLogIamRoleInlinePolicyRoleAttachment0" {
  name = "allow-access-to-cw-logs"
  role = aws_iam_role.CwLogIamRole.id
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
}





resource "aws_cloudwatch_log_group" "CWLogGroupForCloudTrail" {
  name = "CloudTrailLogs"
  retention_in_days = 90
}

resource "aws_config_configuration_recorder" "ConfigurationRecorder" {
  role_arn = aws_iam_role.ConfigIamRole.arn

  recording_group {
    all_supported = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "DeliveryChannel" {
  s3_bucket_name = aws_s3_bucket.S3SharedBucket.id
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]
}

resource "aws_config_configuration_recorder_status" "ConfigurationRecorderStatus" {
  name = aws_config_configuration_recorder.ConfigurationRecorder.name
  is_enabled = true
  depends_on = [ aws_config_delivery_channel.DeliveryChannel ]
}

resource "aws_iam_role" "ConfigIamRole" {
  name = "iamRoleForAWSConfig"
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
                "arn:aws:s3:::s3-bucket-random-name-UMADq/*"
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
            "Resource": "arn:aws:s3:::s3-bucket-random-name-UMADq"
        }
    ]
}
POLICY
}





Terraform support not available at this time

resource "aws_cloudwatch_metric_alarm" "CwAlarm1" {
  alarm_name = "root_account_login"
  alarm_description = "A CloudWatch Alarm that triggers if a root user uses the account."
  metric_name = "RootUserEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "60"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter1" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.userIdentity.type = \"Root\") && ($.userIdentity.invokedBy NOT EXISTS) && ($.eventType != \"AwsServiceEvent\") }"
  name = "RootUserEventCount"

  metric_transformation {
    name = "RootUserEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_config_config_rule" "ConfigRule1" {
  name = "mfa-enabled-for-iam-console-access"
  description = "A Config rule that checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password. The rule is COMPLIANT if MFA is enabled."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }
  scope {
    compliance_resource_types = []
  }
}

resource "aws_config_config_rule" "ConfigRule2" {
  name = "iam-user-unused-credentials-check"
  description = "A config rule that checks whether your AWS Identity and Access Management (IAM) users have passwords or active access keys that have not been used within the specified number of days you provided. Re-evaluating this rule within 4 hours of the first eva..."
  input_parameters = "{\"maxCredentialUsageAge\":\"90\"}"
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  }
  scope {
    compliance_resource_types = []
  }
}

resource "aws_config_config_rule" "ConfigRule3" {
  name = "access-keys-rotated"
  description = "A config rule that checks whether the active access keys are rotated within the number of days specified in maxAccessKeyAge. The rule is NON_COMPLIANT if the access keys have not been rotated for more than maxAccessKeyAge number of days."
  input_parameters = "{\"maxAccessKeyAge\":\"90\"}"
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }
  scope {
    compliance_resource_types = []
  }
}

resource "aws_config_config_rule" "ConfigRule4" {
  name = "iam-password-policy"
  description = "A Config rule that checks whether the account password policy for IAM users meets the specified requirements."
  input_parameters = "{\"RequireUppercaseCharacters\":\"true\",\"RequireLowercaseCharacters\":\"true\",\"RequireSymbols\":\"true\",\"RequireNumbers\":\"true\",\"MinimumPasswordLength\":\"14\",\"PasswordReusePrevention\":\"24\",\"MaxPasswordAge\":\"90\"}"
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }
  scope {
    compliance_resource_types = []
  }
}

resource "aws_config_config_rule" "ConfigRule5" {
  name = "iam-root-access-key-check"
  description = "A config rule that checks whether the root user access key is available. The rule is COMPLIANT if the user access key does not exist."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }
  scope {
    compliance_resource_types = []
  }
}

resource "aws_config_config_rule" "ConfigRule6" {
  name = "root-account-mfa-enabled"
  description = "A Config rule that checks whether users of your AWS account require a multi-factor authentication (MFA) device to sign in with root credentials."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }
  scope {
    compliance_resource_types = []
  }
}

resource "aws_config_config_rule" "ConfigRule7" {
  name = "root-account-hardware-mfa-enabled"
  description = "A config rule that checks whether your AWS account is enabled to use multi-factor authentication (MFA) hardware device to sign in with root credentials. The rule is NON_COMPLIANT if any virtual MFA devices are permitted for signing in with root credent..."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "ROOT_ACCOUNT_HARDWARE_MFA_ENABLED"
  }
  scope {
    compliance_resource_types = []
  }
}

resource "aws_config_config_rule" "ConfigRule8" {
  name = "iam-user-no-policies-check"
  description = "A Config rule that checks that none of your IAM users have policies attached. IAM users must inherit permissions from IAM groups or roles."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "IAM_USER_NO_POLICIES_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::IAM::User"]
  }
}

resource "aws_config_config_rule" "ConfigRule9" {
  name = "ec2_iam_instance_roles"
  description = "A config rule to help you ensure IAM instance roles are used for AWS resource access from instances."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder,aws_lambda_permission.LambdaPermissionConfigRule9 ]

  scope {
    compliance_resource_types = ["AWS::EC2::Instance"]
  }
  source {
    owner = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.LambdaFunctionConfigRule9.arn
    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }
    source_detail {
      event_source = "aws.config"
      message_type = "OversizedConfigurationItemChangeNotification"
    }
  }
}

data "archive_file" "lambda_zip_inline_LambdaFunctionConfigRule9" {
  type = "zip"
  output_path = "/tmp/lambda_zip_inlinetmpfileLambdaFunctionConfigRule9.zip"

  source {
    filename = "index.py"
    content = <<EOF

#==================================================================================================
          # Function: EvaluateInstanceRoleUse
          # Purpose:  Evaluates whether instances use instance roles
          #==================================================================================================
          import boto3
          import json
          def evaluate_compliance(config_item, instance_id):
            if (config_item['resourceType'] != 'AWS::EC2::Instance'): return 'NOT_APPLICABLE'
            if (config_item['configurationItemStatus'] == "ResourceDeleted"): return 'NOT_APPLICABLE'
            reservations = boto3.client('ec2').describe_instances(InstanceIds=[instance_id])['Reservations']
            if (reservations[0]['Instances'][0]['State']['Name']).upper() == 'TERMINATED':
              return 'NOT_APPLICABLE'
            if reservations and 'IamInstanceProfile' in reservations[0]['Instances'][0]: return 'COMPLIANT'
            else: return 'NON_COMPLIANT'
          def lambda_handler(event, context):
            invoking_event = json.loads(event['invokingEvent'])
            compliance_value = 'NOT_APPLICABLE'
            instance_id = invoking_event['configurationItem']['resourceId']
            compliance_value = evaluate_compliance(invoking_event['configurationItem'], instance_id)
            config = boto3.client('config')
            response = config.put_evaluations(
              Evaluations=[
                {
                  'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
                  'ComplianceResourceId': instance_id,
                  'ComplianceType': compliance_value,
                  'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
                },
              ],
              ResultToken=event['resultToken']
            )

EOF

  }
}

resource "aws_lambda_function" "LambdaFunctionConfigRule9" {
  function_name = "LambdaFunctionForec2_iam_instance_roles"
  timeout = "300"
  runtime = "python2.7"
  handler = "index.lambda_handler"
  role = aws_iam_role.LambdaIamRoleConfigRule9.arn
  filename = data.archive_file.lambda_zip_inline_LambdaFunctionConfigRule9.output_path
  source_code_hash = data.archive_file.lambda_zip_inline_LambdaFunctionConfigRule9.output_base64sha256
}

resource "aws_lambda_permission" "LambdaPermissionConfigRule9" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.LambdaFunctionConfigRule9.function_name
  principal = "config.amazonaws.com"
}

resource "aws_iam_role" "LambdaIamRoleConfigRule9" {
  name = "IamRoleForec2_iam_instance_roles"
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

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule9ManagedPolicyRoleAttachment0" {
  role = aws_iam_role.LambdaIamRoleConfigRule9.name
  policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule9ManagedPolicyRoleAttachment1" {
  role = aws_iam_role.LambdaIamRoleConfigRule9.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule9ManagedPolicyRoleAttachment2" {
  role = aws_iam_role.LambdaIamRoleConfigRule9.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRulesExecutionRole"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule9ManagedPolicyRoleAttachment3" {
  role = aws_iam_role.LambdaIamRoleConfigRule9.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}



resource "aws_config_config_rule" "ConfigRule10" {
  name = "iam_support_role"
  description = "A config rule to help you ensure a support role has been created to manage incidents with AWS Support."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder,aws_lambda_permission.LambdaPermissionConfigRule10 ]

  scope {
    compliance_resource_types = ["AWS::IAM::User","AWS::IAM::Role","AWS::IAM::Group"]
  }
  source {
    owner = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.LambdaFunctionConfigRule10.arn
    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }
    source_detail {
      event_source = "aws.config"
      message_type = "OversizedConfigurationItemChangeNotification"
    }
  }
}

data "archive_file" "lambda_zip_inline_LambdaFunctionConfigRule10" {
  type = "zip"
  output_path = "/tmp/lambda_zip_inlinetmpfileLambdaFunctionConfigRule10.zip"

  source {
    filename = "index.py"
    content = <<EOF

import boto3
          import json
          import os
          def evaluate_compliance(resource_type):
            return_value = 'COMPLIANT'
            client = boto3.client('iam')
            partition = 'aws'
            if (os.environ['AWS_REGION'].find("-gov-") > 0):
              partition = 'aws-us-gov'
            policy_arn = 'arn:' + partition + ':iam::aws:policy/AWSSupportAccess'
            print 'policyarn = ', policy_arn
            # If GovCloud, dont evaluate as the Managed Policy 'AWSSupportAccess' doesn't exist
            if (policy_arn.find("-gov") > 0):
              return 'NOT_APPLICABLE'
            # search for all entities that have a specific policy associated: AWSSupportAccess
            response = client.list_entities_for_policy(PolicyArn=policy_arn)
            if (resource_type) == 'user' and len(response['PolicyUsers']) == 0:
              return_value = 'NOT_APPLICABLE'
            elif (resource_type) == 'group' and len(response['PolicyGroups']) == 0:
              return_value = 'NOT_APPLICABLE'
            elif (resource_type) == 'role' and len(response['PolicyRoles']) == 0:
              return_value = 'NOT_APPLICABLE'
            else:
              return_value = 'COMPLIANT'
            return return_value
          def lambda_handler(event, context):
            invoking_event = json.loads(event['invokingEvent'])
            config = boto3.client('config')
            userAnnotation = 'Atleast one IAM User has the AWSSupportAccess IAM policy assigned'
            grpAnnotation = 'Atleast one IAM Group has the AWSSupportAccess IAM policy assigned'
            roleAnnotation = 'Atleast one IAM Role has the AWSSupportAccess IAM policy assigned'
            userCompliance = evaluate_compliance('user')
            groupCompliance = evaluate_compliance('group')
            roleCompliance = evaluate_compliance('role')
            response = config.put_evaluations(
              Evaluations=[
                {
                  'ComplianceResourceType': 'AWS::IAM::User',
                  'ComplianceResourceId': 'NA',
                  'ComplianceType': userCompliance,
                  'Annotation': userAnnotation,
                  'OrderingTimestamp': invoking_event['notificationCreationTime']
                },
                {
                  'ComplianceResourceType': 'AWS::IAM::Group',
                  'ComplianceResourceId': 'NA',
                  'ComplianceType': groupCompliance,
                  'Annotation': grpAnnotation,
                  'OrderingTimestamp': invoking_event['notificationCreationTime']
                },
                {
                  'ComplianceResourceType': 'AWS::IAM::Role',
                  'ComplianceResourceId': 'NA',
                  'ComplianceType': roleCompliance,
                  'Annotation': roleAnnotation,
                  'OrderingTimestamp': invoking_event['notificationCreationTime']
                }
              ],
              ResultToken=event['resultToken']
            )

EOF

  }
}

resource "aws_lambda_function" "LambdaFunctionConfigRule10" {
  function_name = "LambdaFunctionForiam_support_role"
  timeout = "300"
  runtime = "python2.7"
  handler = "index.lambda_handler"
  role = aws_iam_role.LambdaIamRoleConfigRule10.arn
  filename = data.archive_file.lambda_zip_inline_LambdaFunctionConfigRule10.output_path
  source_code_hash = data.archive_file.lambda_zip_inline_LambdaFunctionConfigRule10.output_base64sha256
}

resource "aws_lambda_permission" "LambdaPermissionConfigRule10" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.LambdaFunctionConfigRule10.function_name
  principal = "config.amazonaws.com"
}

resource "aws_iam_role" "LambdaIamRoleConfigRule10" {
  name = "IamRoleForiam_support_role"
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

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule10ManagedPolicyRoleAttachment0" {
  role = aws_iam_role.LambdaIamRoleConfigRule10.name
  policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule10ManagedPolicyRoleAttachment1" {
  role = aws_iam_role.LambdaIamRoleConfigRule10.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRulesExecutionRole"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule10ManagedPolicyRoleAttachment2" {
  role = aws_iam_role.LambdaIamRoleConfigRule10.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}



resource "aws_config_config_rule" "ConfigRule11" {
  name = "iam-policy-no-statements-with-admin-access"
  description = "A config rule that checks whether the default version of AWS Identity and Access Management (IAM) policies do not have administrator access. If any statement has 'Effect': 'Allow' with 'Action': '*' over 'Resource': '*', the rule is NON_COMPLIANT."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }
  scope {
    compliance_resource_types = ["AWS::IAM::Policy"]
  }
}

resource "aws_config_config_rule" "ConfigRule12" {
  name = "multi-region-cloud-trail-enabled"
  description = "A config rule that checks that there is at least one multi-region AWS CloudTrail. The rule is NON_COMPLIANT if the trails do not match inputs parameters."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
  }
  scope {
    compliance_resource_types = []
  }
}

resource "aws_config_config_rule" "ConfigRule13" {
  name = "cloud-trail-log-file-validation-enabled"
  description = "A config rule that checks whether AWS CloudTrail creates a signed digest file with logs. AWS recommends that the file validation must be enabled on all trails. The rule is NON_COMPLIANT if the validation is not enabled."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }
  scope {
    compliance_resource_types = []
  }
}

resource "aws_config_config_rule" "ConfigRule14" {
  name = "cloudtrail_s3_access_logging"
  description = "A config rule that evaluates whether access logging is enabled on the CloudTrail S3 bucket and the S3 bucket is not publicly accessible."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder,aws_lambda_permission.LambdaPermissionConfigRule14 ]

  scope {
    compliance_resource_types = ["AWS::CloudTrail::Trail","AWS::S3::Bucket"]
  }
  source {
    owner = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.LambdaFunctionConfigRule14.arn
    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }
    source_detail {
      event_source = "aws.config"
      message_type = "OversizedConfigurationItemChangeNotification"
    }
  }
}

data "archive_file" "lambda_zip_inline_LambdaFunctionConfigRule14" {
  type = "zip"
  output_path = "/tmp/lambda_zip_inlinetmpfileLambdaFunctionConfigRule14.zip"

  source {
    filename = "index.py"
    content = <<EOF

import json
import boto3
import datetime
import time
from botocore.exceptions import ClientError
def lambda_handler(event, context):
  # get the trail for the current region
  client_ct = boto3.client('cloudtrail')
  for trail in client_ct.describe_trails(includeShadowTrails = False)['trailList']:
    annotation = ''
    is_publicly_accessible = False
    s3_bucket_name = ''
    is_compliant = True
    # check if the cloudtrail s3 bucket is publicly accessible and logged
    if trail['S3BucketName']:
      s3_bucket_name = trail['S3BucketName']
      client_s=boto3.client('s3')
      try:
        for grant in client_s.get_bucket_acl(Bucket = s3_bucket_name)['Grants']:
          # verify cloudtrail s3 bucket ACL
          if grant['Permission'] in ['READ','FULL_CONTROL'] and ('URI' in grant['Grantee'] and ('AuthenticatedUsers' in grant['Grantee']['URI'] or 'AllUsers' in grant['Grantee']['URI'])):
            is_publicly_accessible = True
        if is_publicly_accessible:
          is_compliant = False
          annotation = annotation + ' The CloudTrail S3 bucket '{}' is publicly accessible.'.format(s3_bucket_name)
        # verify cloudtrail s3 bucket logging
        response = client_s.get_bucket_logging(Bucket = s3_bucket_name)
        if 'LoggingEnabled' not in response:
          is_compliant=False
          annotation = annotation + ' The CloudTrail S3 bucket '{}' does not have logging enabled.'.format(s3_bucket_name)
      except Exception as ex:
        print ex
        is_compliant = False
        annotation = annotation + ' There was an error looking up CloudTrail S3 bucket '{}'.'.format(s3_bucket_name)
    else:
      annotation = annotation + ' CloudTrail is not integrated with S3.'
    result_token = 'No token found.'
    if 'resultToken' in event: result_token = event['resultToken']
    evaluations = [
      {
        'ComplianceResourceType': 'AWS::S3::Bucket',
        'ComplianceResourceId': s3_bucket_name,
        'ComplianceType': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
        'OrderingTimestamp': datetime.datetime.now()
      }
    ]
    if is_compliant: annotation = 'Acces logging is enabled on the CloudTrail S3 bucket '{}' and the S3 bucket is not publicly accessible'.format(s3_bucket_name)
    if annotation: evaluations[0]['Annotation'] = annotation
    config = boto3.client('config')
    config.put_evaluations(
      Evaluations = evaluations,
      ResultToken = result_token
    )

EOF

  }
}

resource "aws_lambda_function" "LambdaFunctionConfigRule14" {
  function_name = "LambdaFunctionForcloudtrail_s3_access_logging"
  timeout = "300"
  runtime = "python2.7"
  handler = "index.lambda_handler"
  role = aws_iam_role.LambdaIamRoleConfigRule14.arn
  filename = data.archive_file.lambda_zip_inline_LambdaFunctionConfigRule14.output_path
  source_code_hash = data.archive_file.lambda_zip_inline_LambdaFunctionConfigRule14.output_base64sha256
}

resource "aws_lambda_permission" "LambdaPermissionConfigRule14" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.LambdaFunctionConfigRule14.function_name
  principal = "config.amazonaws.com"
}

resource "aws_iam_role" "LambdaIamRoleConfigRule14" {
  name = "IamRoleForcloudtrail_s3_access_logging"
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

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule14ManagedPolicyRoleAttachment0" {
  role = aws_iam_role.LambdaIamRoleConfigRule14.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCloudTrailReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule14ManagedPolicyRoleAttachment1" {
  role = aws_iam_role.LambdaIamRoleConfigRule14.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule14ManagedPolicyRoleAttachment2" {
  role = aws_iam_role.LambdaIamRoleConfigRule14.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRulesExecutionRole"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule14ManagedPolicyRoleAttachment3" {
  role = aws_iam_role.LambdaIamRoleConfigRule14.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}



resource "aws_config_config_rule" "ConfigRule15" {
  name = "cloud-trail-cloud-watch-logs-enabled"
  description = "A config rule that checks whether AWS CloudTrail trails are configured to send logs to Amazon CloudWatch Logs. The trail is NON_COMPLIANT if the CloudWatchLogsLogGroupArn property of the trail is empty."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED"
  }
  scope {
    compliance_resource_types = []
  }
}

resource "aws_config_config_rule" "ConfigRule16" {
  name = "cloud-trail-encryption-enabled"
  description = "A config rule that checks whether AWS CloudTrail is configured to use the server side encryption (SSE) AWS Key Management Service (AWS KMS) customer master key (CMK) encryption. The rule is COMPLIANT if the KmsKeyId is defined."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
  }
  scope {
    compliance_resource_types = []
  }
}

resource "aws_config_config_rule" "ConfigRule17" {
  name = "cmk-backing-key-rotation-enabled"
  description = "A config rule that checks that key rotation is enabled for each customer master key (CMK). The rule is COMPLIANT, if the key rotation is enabled for specific key object. The rule is not applicable to CMKs that have imported key material."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }
  scope {
    compliance_resource_types = []
  }
}

resource "aws_config_config_rule" "ConfigRule18" {
  name = "vpc-flow-logs-enabled"
  description = "A config rule that checks whether Amazon Virtual Private Cloud flow logs are found and enabled for Amazon VPC."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }
  scope {
    compliance_resource_types = []
  }
}

resource "aws_cloudwatch_metric_alarm" "CwAlarm2" {
  alarm_name = "unauthorized_api_calls"
  alarm_description = "A CloudWatch Alarm that triggers if Multiple unauthorized actions or logins attempted."
  metric_name = "UnauthorizedAttemptCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "60"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter2" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  name = "UnauthorizedAttemptCount"

  metric_transformation {
    name = "UnauthorizedAttemptCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm3" {
  alarm_name = "no_mfa_console_logins"
  alarm_description = "A CloudWatch Alarm that triggers if there is a Management Console sign-in without MFA."
  metric_name = "ConsoleSigninWithoutMFA"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "60"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter3" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.responseElements.ConsoleLogin != \"Failure\") && ($.additionalEventData.SamlProviderArn NOT EXISTS) }"
  name = "ConsoleSigninWithoutMFA"

  metric_transformation {
    name = "ConsoleSigninWithoutMFA"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm4" {
  alarm_name = "iam_policy_changes"
  alarm_description = "A CloudWatch Alarm that triggers when changes are made to IAM policies. Events include IAM policy creation/deletion/update operations as well as attaching/detaching policies from IAM users, roles or groups."
  metric_name = "IAMPolicyEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter4" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  name = "IAMPolicyEventCount"

  metric_transformation {
    name = "IAMPolicyEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm5" {
  alarm_name = "cloudtrail_changes"
  alarm_description = "A CloudWatch Alarm that triggers when changes are made to CloudTrail."
  metric_name = "CloudTrailEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter5" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
  name = "CloudTrailEventCount"

  metric_transformation {
    name = "CloudTrailEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm6" {
  alarm_name = "failed_console_logins"
  alarm_description = "A CloudWatch Alarm that triggers if there are AWS Management Console authentication failures."
  metric_name = "ConsoleLoginFailures"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter6" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
  name = "ConsoleLoginFailures"

  metric_transformation {
    name = "ConsoleLoginFailures"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm7" {
  alarm_name = "disabled_deleted_cmks"
  alarm_description = "A CloudWatch Alarm that triggers if customer created CMKs get disabled or scheduled for deletion."
  metric_name = "KMSCustomerKeyDeletion"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "60"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter7" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventSource = kms.amazonaws.com) &&  (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion)) }"
  name = "KMSCustomerKeyDeletion"

  metric_transformation {
    name = "KMSCustomerKeyDeletion"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm8" {
  alarm_name = "s3_changes"
  alarm_description = "A CloudWatch Alarm that triggers when changes are made to an S3 Bucket."
  metric_name = "S3BucketActivityEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter8" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
  name = "S3BucketActivityEventCount"

  metric_transformation {
    name = "S3BucketActivityEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm9" {
  alarm_name = "config_changes"
  alarm_description = "A CloudWatch Alarm that triggers when changes are made to AWS Config."
  metric_name = "CloudTrailEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter9" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventName = PutConfigurationRecorder) || ($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) }"
  name = "CloudTrailEventCount"

  metric_transformation {
    name = "CloudTrailEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm10" {
  alarm_name = "securitygroup_changes"
  alarm_description = "A CloudWatch Alarm that triggers when changes are made to Security Groups."
  metric_name = "SecurityGroupEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter10" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
  name = "SecurityGroupEventCount"

  metric_transformation {
    name = "SecurityGroupEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm11" {
  alarm_name = "nacl_changes"
  alarm_description = "A CloudWatch Alarm that triggers when changes are made to Network ACLs."
  metric_name = "NetworkAclEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter11" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
  name = "NetworkAclEventCount"

  metric_transformation {
    name = "NetworkAclEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm12" {
  alarm_name = "igw_changes"
  alarm_description = "A CloudWatch Alarm that triggers when changes are made to an Internet Gateway in a VPC."
  metric_name = "GatewayEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter12" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
  name = "GatewayEventCount"

  metric_transformation {
    name = "GatewayEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm13" {
  alarm_name = "vpc_routetable_changes"
  alarm_description = "A CloudWatch Alarm that triggers when changes are made to a VPC's Route Table."
  metric_name = "VpcRouteTableEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter13" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventName = AssociateRouteTable) || ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DeleteRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DisassociateRouteTable) }"
  name = "VpcRouteTableEventCount"

  metric_transformation {
    name = "VpcRouteTableEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm14" {
  alarm_name = "vpc_changes"
  alarm_description = "A CloudWatch Alarm that triggers when changes are made to a VPC."
  metric_name = "VpcEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter14" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
  name = "VpcEventCount"

  metric_transformation {
    name = "VpcEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_config_config_rule" "ConfigRule19" {
  name = "restricted-ssh"
  description = "A Config rule that checks whether security groups in use do not allow restricted incoming SSH traffic. This rule applies only to IPv4."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::SecurityGroup"]
  }
}

resource "aws_config_config_rule" "ConfigRule20" {
  name = "restricted-common-ports"
  description = "A Config rule that checks whether security groups in use do not allow restricted incoming TCP traffic to the specified ports. This rule applies only to IPv4."
  input_parameters = "{\"blockedPort1\":\"20\",\"blockedPort2\":\"21\",\"blockedPort3\":\"3389\",\"blockedPort4\":\"3306\",\"blockedPort5\":\"4333\"}"
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::SecurityGroup"]
  }
}

resource "aws_config_config_rule" "ConfigRule21" {
  name = "vpc-default-security-group-closed"
  description = "A config rule that checks that the default security group of any Amazon Virtual Private Cloud (VPC) does not allow inbound or outbound traffic. The rule returns NOT_APPLICABLE if the security group is not default. The rule is NON_COMPLIANT if the defau..."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::SecurityGroup"]
  }
}

resource "aws_config_config_rule" "ConfigRule22" {
  name = "vpc_peering_least_access"
  description = "A config rule to help you ensure routing tables for VPC peering are 'least access'"
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder,aws_lambda_permission.LambdaPermissionConfigRule22 ]

  scope {
    compliance_resource_types = ["AWS::EC2::RouteTable"]
  }
  source {
    owner = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.LambdaFunctionConfigRule22.arn
    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }
    source_detail {
      event_source = "aws.config"
      message_type = "OversizedConfigurationItemChangeNotification"
    }
  }
}

data "archive_file" "lambda_zip_inline_LambdaFunctionConfigRule22" {
  type = "zip"
  output_path = "/tmp/lambda_zip_inlinetmpfileLambdaFunctionConfigRule22.zip"

  source {
    filename = "index.py"
    content = <<EOF

          #==================================================================================================
          # Function: EvaluateVpcPeeringRouteTables
          # Purpose:  Evaluates whether VPC route tables are least access
          #==================================================================================================
          import boto3
          import json
          def lambda_handler(event, context):
            is_compliant = True
            invoking_event = json.loads(event['invokingEvent'])
            annotation = ''
            route_table_id = invoking_event['configurationItem']['resourceId']
            #print (json.dumps(boto3.client('ec2').describe_route_tables(RouteTableIds=[route_table_id])))
            for route_table in boto3.client('ec2').describe_route_tables(RouteTableIds=[route_table_id])['RouteTables']:
              for route in route_table['Routes']:
                if 'VpcPeeringConnectionId' in route:
                  if int(str(route['DestinationCidrBlock']).split("/", 1)[1]) < 24:
                    is_compliant = False
                    annotation = 'VPC peered route table has a large CIDR block destination.'
              evaluations = [
                {
                  'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
                  'ComplianceResourceId': route_table_id,
                  'ComplianceType': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
                  'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
                }
              ]
              if annotation: evaluations[0]['Annotation'] = annotation
              response = boto3.client('config').put_evaluations(
              Evaluations = evaluations,
              ResultToken = event['resultToken'])

EOF

  }
}

resource "aws_lambda_function" "LambdaFunctionConfigRule22" {
  function_name = "LambdaFunctionForvpc_peering_least_access"
  timeout = "300"
  runtime = "python2.7"
  handler = "index.lambda_handler"
  role = aws_iam_role.LambdaIamRoleConfigRule22.arn
  filename = data.archive_file.lambda_zip_inline_LambdaFunctionConfigRule22.output_path
  source_code_hash = data.archive_file.lambda_zip_inline_LambdaFunctionConfigRule22.output_base64sha256
}

resource "aws_lambda_permission" "LambdaPermissionConfigRule22" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.LambdaFunctionConfigRule22.function_name
  principal = "config.amazonaws.com"
}

resource "aws_iam_role" "LambdaIamRoleConfigRule22" {
  name = "IamRoleForvpc_peering_least_access"
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

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule22ManagedPolicyRoleAttachment0" {
  role = aws_iam_role.LambdaIamRoleConfigRule22.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule22ManagedPolicyRoleAttachment1" {
  role = aws_iam_role.LambdaIamRoleConfigRule22.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRulesExecutionRole"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule22ManagedPolicyRoleAttachment2" {
  role = aws_iam_role.LambdaIamRoleConfigRule22.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
