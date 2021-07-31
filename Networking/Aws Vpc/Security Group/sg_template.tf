provider "aws" {
}

resource "aws_security_group" "Template Security Group" {
  name = "Template Security Group"
  description = "Build a custom security group."
  vpc_id = "1234561234"



}