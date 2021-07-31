provider "aws" {
}

resource "aws_security_group" "sg_allow_mariadb" {
  name = "sg_allow_mariadb"
  description = "A security group that allows inbound access to a Maria DB instance."
  vpc_id = "12345"

  ingress {
    from_port = 3306
    to_port = 3306
    protocol = "tcp"
    cidr_blocks = [""]
    description = "Allow connections to a MariaDB instance"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}