# 🚀 Create VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.vpc_name }
}

# 🚀 Internet Gateway (for Public Subnets)
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.vpc_name}-igw" }
}

# 🚀 Subnets (Public, Private, Database, Cache)
resource "aws_subnet" "public" {
  count = var.create_public_subnets ? length(var.public_subnets) : 0
  vpc_id = aws_vpc.main.id
  cidr_block = var.public_subnets[count.index]
  map_public_ip_on_launch = true
  availability_zone = var.azs[count.index]
  tags = { Name = "${var.vpc_name}-public-${count.index + 1}" }
}

resource "aws_subnet" "private" {
  count = var.create_private_subnets ? length(var.private_subnets) : 0
  vpc_id = aws_vpc.main.id
  cidr_block = var.private_subnets[count.index]
  availability_zone = var.azs[count.index]
  tags = { Name = "${var.vpc_name}-private-${count.index + 1}" }
}

resource "aws_subnet" "database" {
  count = var.create_database_subnets ? length(var.database_subnets) : 0
  vpc_id = aws_vpc.main.id
  cidr_block = var.database_subnets[count.index]
  availability_zone = var.azs[count.index]
  tags = { Name = "${var.vpc_name}-database-${count.index + 1}" }
}

resource "aws_subnet" "cache" {
  count = var.create_cache_subnets ? length(var.cache_subnets) : 0
  vpc_id = aws_vpc.main.id
  cidr_block = var.cache_subnets[count.index]
  availability_zone = var.azs[count.index]
  tags = { Name = "${var.vpc_name}-cache-${count.index + 1}" }
}

# 🚀 Security Groups for VPC Endpoints
resource "aws_security_group" "vpc_endpoint_sg" {
  for_each = var.enable_vpc_endpoints ? toset(["public", "private", "database", "cache"]) : []

  vpc_id = aws_vpc.main.id
  name   = "${var.vpc_name}-vpce-sg-${each.key}"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.vpc_name}-vpce-sg-${each.key}" }
}

# 🚀 VPC Endpoints (Optional)
# resource "aws_vpc_endpoint" "endpoints" {
#   for_each = var.enable_vpc_endpoints ? toset(var.vpc_endpoint_services) : {}

#   vpc_id            = aws_vpc.main.id
#   service_name      = "com.amazonaws.${var.region}.${each.key}"
#   vpc_endpoint_type = lookup(var.vpc_endpoint_types, each.key, "Interface")

#   subnet_ids = lookup(var.vpc_endpoint_subnet_types, each.key, "private") == "public" ? aws_subnet.public[*].id :
#                lookup(var.vpc_endpoint_subnet_types, each.key, "private") == "private" ? aws_subnet.private[*].id :
#                lookup(var.vpc_endpoint_subnet_types, each.key, "private") == "database" ? aws_subnet.database[*].id :
#                aws_subnet.cache[*].id

#   private_dns_enabled = true
#   security_group_ids  = length(var.vpc_endpoint_sg_ids) > 0 ? var.vpc_endpoint_sg_ids : [aws_security_group.vpc_endpoint_sg[lookup(var.vpc_endpoint_subnet_types, each.key, "private")].id]

#   tags = { Name = "${var.vpc_name}-vpce-${each.key}" }
# }

resource "aws_vpc_endpoint" "endpoints" {
  for_each = var.enable_vpc_endpoints ? toset(var.vpc_endpoint_services) : {}

  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type = lookup(var.vpc_endpoint_types, each.key, "Interface")

  subnet_ids = lookup(var.vpc_endpoint_subnet_types, each.key, "public") == "public" ? aws_subnet.public[*].id :
               lookup(var.vpc_endpoint_subnet_types, each.key, "private") == "private" ? aws_subnet.private[*].id :
               lookup(var.vpc_endpoint_subnet_types, each.key, "database ") == "database" ? aws_subnet.database[*].id :
               aws_subnet.cache[*].id

  private_dns_enabled = true

  security_group_ids = length(var.vpc_endpoint_sg_ids) > 0 ? var.vpc_endpoint_sg_ids :
                       [aws_security_group.vpc_endpoint_sg[lookup(var.vpc_endpoint_subnet_types, each.key, "private")].id]

  tags = { Name = "${var.vpc_name}-vpce-${each.key}" }
}

# 🚀 VPC Flow Logs (Optional)
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  count = var.enable_vpc_flow_logs ? 1 : 0
  name  = "/aws/vpc/${var.vpc_name}-flow-logs"
  retention_in_days = var.flow_logs_retention
}

resource "aws_flow_log" "vpc_flow_log" {
  count = var.enable_vpc_flow_logs ? 1 : 0
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs[0].arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}

# 🚀 Security Groups for VPC Endpoints (Created Dynamically If Enabled)
resource "aws_security_group" "vpc_endpoint_sg" {
  for_each = var.create_security_groups ? toset(["public", "private", "database", "cache"]) : {}

  vpc_id = aws_vpc.main.id
  name   = "${var.vpc_name}-vpce-sg-${each.key}"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.vpc_name}-vpce-sg-${each.key}" }
}
