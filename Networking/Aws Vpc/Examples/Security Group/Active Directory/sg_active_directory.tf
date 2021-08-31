provider "aws" {
}

resource "aws_security_group" "sg_active_directory" {
  name = "sg_active_directory"
  description = "A security group that allows domain controller services on Microsoft Active Directory servers."
  vpc_id = ""

  ingress {
    from_port = 9389
    to_port = 9389
    protocol = "tcp"
    cidr_blocks = [""]
    description = "Active Directory Web Services (ADWS) / Active Directory Management Gateway Service"
  }
  ingress {
    from_port = 3269
    to_port = 3269
    protocol = "tcp"
    cidr_blocks = [""]
    description = "Global Catalog"
  }
  ingress {
    from_port = 3268
    to_port = 3268
    protocol = "tcp"
    cidr_blocks = [""]
    description = "Global Catalog"
  }
  ingress {
    from_port = 0
    to_port = 0
    protocol = "icmp"
    cidr_blocks = [""]
    description = "ICMP"
  }
  ingress {
    from_port = 389
    to_port = 389
    protocol = "tcp"
    cidr_blocks = [""]
    description = "LDAP Server"
  }
  ingress {
    from_port = 389
    to_port = 389
    protocol = "udp"
    cidr_blocks = [""]
    description = "LDAP Server"
  }
  ingress {
    from_port = 636
    to_port = 636
    protocol = "tcp"
    cidr_blocks = [""]
    description = "LDAP Server (SSL)"
  }
  ingress {
    from_port = 445
    to_port = 445
    protocol = "tcp"
    cidr_blocks = [""]
    description = "SMB"
  }
  ingress {
    from_port = 135
    to_port = 135
    protocol = "tcp"
    cidr_blocks = [""]
    description = "RPC"
  }
  ingress {
    from_port = 1024
    to_port = 5000
    protocol = "tcp"
    cidr_blocks = [""]
    description = "RPC randomly allocated tcp high ports"
  }
  ingress {
    from_port = 49152
    to_port = 65535
    protocol = "tcp"
    cidr_blocks = [""]
    description = "RPC randomly allocated tcp high ports"
  }
  ingress {
    from_port = 500
    to_port = 500
    protocol = "udp"
    cidr_blocks = [""]
    description = "IPSec ISAKMP"
  }
  ingress {
    from_port = 4500
    to_port = 4500
    protocol = "udp"
    cidr_blocks = [""]
    description = "NAT-T"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}