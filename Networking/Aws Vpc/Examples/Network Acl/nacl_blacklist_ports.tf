provider "aws" {
}

resource "aws_network_acl" "NetworkAcl" {
  vpc_id = "1234561234"

  ingress {
    from_port = 
    to_port = 
    protocol = "tcp"
    action = "deny"
    rule_no = 100
    cidr_block = "0.0.0.0/0"
  }
  ingress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    action = "allow"
    rule_no = 200
    cidr_block = "0.0.0.0/0"
  }

  egress {
    from_port = 
    to_port = 
    protocol = "tcp"
    action = "deny"
    rule_no = 100
    cidr_block = "0.0.0.0/0"
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    action = "allow"
    rule_no = 200
    cidr_block = "0.0.0.0/0"
  }

  tags = {
    Name = "Change my name"
  }
}