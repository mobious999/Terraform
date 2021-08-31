provider "aws" {
  region  = "us-east-2"
}

resource "aws_guardduty_detector" "GuardDuty" {
  enable = true
}