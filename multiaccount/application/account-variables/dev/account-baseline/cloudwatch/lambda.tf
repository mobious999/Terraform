resource "aws_iam_role" "cloudwatch_cleanup_role" {
  name               = "cloudwatch_cleanup_role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_policy" "cloudwatch_cleanup_policy" {
  name        = "lambda_cloudwatch_cleanup"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:DeleteLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*",
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "cleanup_lambda_policy" {
  role       = aws_iam_role.cloudwatch_cleanup_role.name
  policy_arn = aws_iam_policy.cloudwatch_cleanup_policy.arn
}

data "archive_file" "cloudwatch_cleanup_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/cleanup.py"
  output_path = "cleanup.zip"
}

resource "aws_lambda_function" "cloudwatch_cleanup_lambda" {
  filename         = "cleanup.zip"
//  source_code_hash = filebase64sha256("cleanup.zip")
  function_name    = "cloudwatch_cleanup"
  role             = aws_iam_role.cloudwatch_cleanup_role.arn
  handler          = "cleanup.handler"
  runtime          = "python3.8"
  timeout          = 300 # 5 mins in seconds
}

resource "aws_cloudwatch_event_rule" "trigger_cloudwatch_cleanup" {
  name                = "cloudwatch_cleanup_trigger"
  description         = "Cron event to trigger cleanup of empty Cloudwatch log groups"
  schedule_expression = "cron(0 8 * * ? *)" # daily 8 AM UTC, 3 AM EST
}

resource "aws_cloudwatch_event_target" "cloudwatch_cleanup_lambda_trigger_target" {
  arn  = aws_lambda_function.cloudwatch_cleanup_lambda.arn
  rule = aws_cloudwatch_event_rule.trigger_cloudwatch_cleanup.name
}

resource "aws_lambda_permission" "allow_cloudwatch_cleanup_lambda" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cloudwatch_cleanup_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.trigger_cloudwatch_cleanup.arn
}