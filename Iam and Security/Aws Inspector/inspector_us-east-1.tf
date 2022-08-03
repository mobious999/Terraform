provider "aws" {
  region  = "us-east-1"
}

resource "aws_inspector_assessment_template" "AssessmentTemplate" {
  name = "default"
  duration = 3600
  rules_package_arns = ["arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gEjTy7T7","arn:aws:inspector:us-east-1:316112463485:rulespackage/0-rExsr2X8","arn:aws:inspector:us-east-1:316112463485:rulespackage/0-PmNV0Tcd","arn:aws:inspector:us-east-1:316112463485:rulespackage/0-R01qwB5Q","arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gBONHN9h"]
  target_arn = aws_inspector_assessment_target.AssessmentTargetForAssessmentTemplate.arn
}

resource "aws_inspector_assessment_target" "AssessmentTargetForAssessmentTemplate" {
  name = "Amazon Inspector Targets"
}
