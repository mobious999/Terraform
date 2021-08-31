provider "aws" {
}

resource "aws_network_acl" "NetworkAcl" {
  vpc_id = "1234561234"



  tags = {
    Name = "change my name"
  }
}