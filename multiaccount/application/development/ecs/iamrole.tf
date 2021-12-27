resource "aws_iam_role" "ExecutionRole" {
  name = "${var.ecs_name}ExecutionRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    Name      = "${var.ecs_name}ExecutionRole"
    Terraform = "true"
  }
}