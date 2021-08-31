provider "aws" {
  region  = "us-east-2"
}

data "aws_availability_zones" "available" {
		  state = "available"
		}

resource "aws_vpc" "VPC" {
  cidr_block = "10.0.0.0/16"
  enable_dns_support = true
  enable_dns_hostnames = true
}



resource "aws_subnet" "PublicSubnet1" {
  cidr_block = "10.0.0.0/24"
  map_public_ip_on_launch = false
  vpc_id = aws_vpc.VPC.id
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "Public Subnet AZ A"
  }
}



resource "aws_subnet" "PublicSubnet2" {
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = false
  vpc_id = aws_vpc.VPC.id
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "Public Subnet AZ B"
  }
}



resource "aws_subnet" "PublicSubnet3" {
  cidr_block = "10.0.2.0/24"
  map_public_ip_on_launch = false
  vpc_id = aws_vpc.VPC.id
  availability_zone = data.aws_availability_zones.available.names[2]

  tags = {
    Name = "Public Subnet AZ C"
  }
}



resource "aws_subnet" "PublicSubnet4" {
  cidr_block = "10.0.3.0/24"
  map_public_ip_on_launch = false
  vpc_id = aws_vpc.VPC.id
  availability_zone = data.aws_availability_zones.available.names[3]

  tags = {
    Name = "Public Subnet AZ D"
  }
}



resource "aws_subnet" "PrivateSubnet1" {
  cidr_block = "10.0.10.0/24"
  map_public_ip_on_launch = false
  vpc_id = aws_vpc.VPC.id
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "Private Subnet AZ A"
  }
}



resource "aws_subnet" "PrivateSubnet2" {
  cidr_block = "10.0.11.0/24"
  map_public_ip_on_launch = false
  vpc_id = aws_vpc.VPC.id
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "Private Subnet AZ B"
  }
}



resource "aws_subnet" "PrivateSubnet3" {
  cidr_block = "10.0.12.0/24"
  map_public_ip_on_launch = false
  vpc_id = aws_vpc.VPC.id
  availability_zone = data.aws_availability_zones.available.names[2]

  tags = {
    Name = "Private Subnet AZ C"
  }
}



resource "aws_subnet" "PrivateSubnet4" {
  cidr_block = "10.0.13.0/24"
  map_public_ip_on_launch = false
  vpc_id = aws_vpc.VPC.id
  availability_zone = data.aws_availability_zones.available.names[3]

  tags = {
    Name = "Private Subnet AZ D"
  }
}

resource "aws_route_table" "RouteTablePublic" {
  vpc_id = aws_vpc.VPC.id
  depends_on = [ aws_internet_gateway.Igw ]

  tags = {
    Name = "Public Route Table"
  }

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.Igw.id
  }
}

resource "aws_route_table_association" "AssociationForRouteTablePublic0" {
  subnet_id = aws_subnet.PublicSubnet1.id
  route_table_id = aws_route_table.RouteTablePublic.id
}

resource "aws_route_table_association" "AssociationForRouteTablePublic1" {
  subnet_id = aws_subnet.PublicSubnet2.id
  route_table_id = aws_route_table.RouteTablePublic.id
}

resource "aws_route_table_association" "AssociationForRouteTablePublic2" {
  subnet_id = aws_subnet.PublicSubnet3.id
  route_table_id = aws_route_table.RouteTablePublic.id
}

resource "aws_route_table_association" "AssociationForRouteTablePublic3" {
  subnet_id = aws_subnet.PublicSubnet4.id
  route_table_id = aws_route_table.RouteTablePublic.id
}



resource "aws_route_table" "RouteTablePrivate1" {
  vpc_id = aws_vpc.VPC.id
  depends_on = [ aws_nat_gateway.NatGw1 ]

  tags = {
    Name = "Private Route Table A"
  }

  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.NatGw1.id
  }
}

resource "aws_route_table_association" "AssociationForRouteTablePrivate10" {
  subnet_id = aws_subnet.PrivateSubnet1.id
  route_table_id = aws_route_table.RouteTablePrivate1.id
}



resource "aws_route_table" "RouteTablePrivate2" {
  vpc_id = aws_vpc.VPC.id
  depends_on = [ aws_nat_gateway.NatGw1 ]

  tags = {
    Name = "Private Route Table B"
  }

  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.NatGw1.id
  }
}

resource "aws_route_table_association" "AssociationForRouteTablePrivate20" {
  subnet_id = aws_subnet.PrivateSubnet2.id
  route_table_id = aws_route_table.RouteTablePrivate2.id
}



resource "aws_route_table" "RouteTablePrivate3" {
  vpc_id = aws_vpc.VPC.id
  depends_on = [ aws_nat_gateway.NatGw1 ]

  tags = {
    Name = "Private Route Table C"
  }

  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.NatGw1.id
  }
}

resource "aws_route_table_association" "AssociationForRouteTablePrivate30" {
  subnet_id = aws_subnet.PrivateSubnet3.id
  route_table_id = aws_route_table.RouteTablePrivate3.id
}



resource "aws_route_table" "RouteTablePrivate4" {
  vpc_id = aws_vpc.VPC.id
  depends_on = [ aws_nat_gateway.NatGw1 ]

  tags = {
    Name = "Private Route Table D"
  }

  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.NatGw1.id
  }
}

resource "aws_route_table_association" "AssociationForRouteTablePrivate40" {
  subnet_id = aws_subnet.PrivateSubnet4.id
  route_table_id = aws_route_table.RouteTablePrivate4.id
}



resource "aws_internet_gateway" "Igw" {
  vpc_id = aws_vpc.VPC.id
}

resource "aws_eip" "EipForNatGw1" {
}

resource "aws_nat_gateway" "NatGw1" {
  allocation_id = aws_eip.EipForNatGw1.id
  subnet_id = aws_subnet.PublicSubnet1.id

  tags = {
    Name = "NAT GW A"
  }
}

resource "aws_eip" "EipForNatGw2" {
}

resource "aws_nat_gateway" "NatGw2" {
  allocation_id = aws_eip.EipForNatGw2.id
  subnet_id = aws_subnet.PublicSubnet2.id

  tags = {
    Name = "NAT GW B"
  }
}

resource "aws_eip" "EipForNatGw3" {
}

resource "aws_nat_gateway" "NatGw3" {
  allocation_id = aws_eip.EipForNatGw3.id
  subnet_id = aws_subnet.PublicSubnet3.id

  tags = {
    Name = "NAT GW C"
  }
}

resource "aws_eip" "EipForNatGw4" {
}

resource "aws_nat_gateway" "NatGw4" {
  allocation_id = aws_eip.EipForNatGw4.id
  subnet_id = aws_subnet.PublicSubnet4.id

  tags = {
    Name = "NAT GW D"
  }
}

resource "aws_flow_log" "FlowLogs" {
  traffic_type = "ALL"
  log_destination_type = "cloud-watch-logs"
  vpc_id = aws_vpc.VPC.id
  log_destination = aws_cloudwatch_log_group.CwLogGroup.arn
  iam_role_arn = aws_iam_role.CwLogIamRole.arn
}

resource "aws_cloudwatch_log_group" "CwLogGroup" {
  name = "FlowLogs"
}

resource "aws_iam_role" "CwLogIamRole" {
  name = "iamRoleFlowLogsToCloudWatchLogs"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["vpc-flow-logs.amazonaws.com"]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "CwLogIamRoleInlinePolicyRoleAttachment0" {
  name = "allow-access-to-cw-logs"
  role = aws_iam_role.CwLogIamRole.id
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "FlowLogsCreateLogStream2014110",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
}



resource "aws_vpc_endpoint" "s3VPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids = [ aws_route_table.RouteTablePublic.id,aws_route_table.RouteTablePrivate1.id,aws_route_table.RouteTablePrivate2.id,aws_route_table.RouteTablePrivate3.id,aws_route_table.RouteTablePrivate4.id ]
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "*"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
POLICY
}

resource "aws_vpc_endpoint" "dynamodbVPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids = [ aws_route_table.RouteTablePublic.id,aws_route_table.RouteTablePrivate1.id,aws_route_table.RouteTablePrivate2.id,aws_route_table.RouteTablePrivate3.id,aws_route_table.RouteTablePrivate4.id ]
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "*"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
POLICY
}

resource "aws_vpc_endpoint" "ec2VPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.ec2"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgForec2VPCEndpoint.id ]
}

resource "aws_security_group" "SgForec2VPCEndpoint" {
  name = "SgForec2VPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_vpc_endpoint" "cloudtrailVPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.cloudtrail"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgForcloudtrailVPCEndpoint.id ]
}

resource "aws_security_group" "SgForcloudtrailVPCEndpoint" {
  name = "SgForcloudtrailVPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_vpc_endpoint" "ec2VPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.ec2"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgForec2VPCEndpoint.id ]
}

resource "aws_security_group" "SgForec2VPCEndpoint" {
  name = "SgForec2VPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_vpc_endpoint" "ec2messagesVPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.ec2messages"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgForec2messagesVPCEndpoint.id ]
}

resource "aws_security_group" "SgForec2messagesVPCEndpoint" {
  name = "SgForec2messagesVPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_vpc_endpoint" "eventsVPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.events"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgForeventsVPCEndpoint.id ]
}

resource "aws_security_group" "SgForeventsVPCEndpoint" {
  name = "SgForeventsVPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_vpc_endpoint" "kmsVPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.kms"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgForkmsVPCEndpoint.id ]
}

resource "aws_security_group" "SgForkmsVPCEndpoint" {
  name = "SgForkmsVPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_vpc_endpoint" "logsVPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.logs"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgForlogsVPCEndpoint.id ]
}

resource "aws_security_group" "SgForlogsVPCEndpoint" {
  name = "SgForlogsVPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_vpc_endpoint" "monitoringVPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.monitoring"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgFormonitoringVPCEndpoint.id ]
}

resource "aws_security_group" "SgFormonitoringVPCEndpoint" {
  name = "SgFormonitoringVPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_vpc_endpoint" "secretsmanagerVPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.secretsmanager"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgForsecretsmanagerVPCEndpoint.id ]
}

resource "aws_security_group" "SgForsecretsmanagerVPCEndpoint" {
  name = "SgForsecretsmanagerVPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_vpc_endpoint" "snsVPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.sns"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgForsnsVPCEndpoint.id ]
}

resource "aws_security_group" "SgForsnsVPCEndpoint" {
  name = "SgForsnsVPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_vpc_endpoint" "sqsVPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.sqs"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgForsqsVPCEndpoint.id ]
}

resource "aws_security_group" "SgForsqsVPCEndpoint" {
  name = "SgForsqsVPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_vpc_endpoint" "ssmVPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.ssm"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgForssmVPCEndpoint.id ]
}

resource "aws_security_group" "SgForssmVPCEndpoint" {
  name = "SgForssmVPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_vpc_endpoint" "ssmmessagesVPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.ssmmessages"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgForssmmessagesVPCEndpoint.id ]
}

resource "aws_security_group" "SgForssmmessagesVPCEndpoint" {
  name = "SgForssmmessagesVPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_vpc_endpoint" "stsVPCEndpoint" {
  vpc_id = aws_vpc.VPC.id
  service_name = "com.amazonaws.us-east-2.sts"
  vpc_endpoint_type = "Interface"
  subnet_ids = [ aws_subnet.PublicSubnet1.id,aws_subnet.PublicSubnet2.id,aws_subnet.PublicSubnet3.id,aws_subnet.PublicSubnet4.id ]
  security_group_ids = [ aws_security_group.SgForstsVPCEndpoint.id ]
}

resource "aws_security_group" "SgForstsVPCEndpoint" {
  name = "SgForstsVPCEndpoint"
  description = "Security Group for VPC Endpoint"
  vpc_id = aws_vpc.VPC.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic to VPC Endpoint"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}