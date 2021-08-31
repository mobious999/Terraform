provider "aws" {
}

resource "aws_security_group" "allow-mysql-traffic" {
  name = "allow-mysql-traffic"
  description = "A security group that allows inbound access to a MySQL DB instance."
  vpc_id = ""

  ingress {
    from_port = 3306
    to_port = 3306
    protocol = "tcp"
    cidr_blocks = [""]
    description = "Allow connections to a MySql DB instance"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}