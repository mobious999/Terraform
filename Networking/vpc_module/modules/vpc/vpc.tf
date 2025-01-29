resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = var.vpc_name }
}

# 🚀 Subnets (Dynamically Scales with AZ count)
resource "aws_subnet" "public" {
  count = var.create_public_subnets ? length(var.azs) : 0
  vpc_id = aws_vpc.main.id
  cidr_block = var.public_subnets[count.index]
  availability_zone = var.azs[count.index]
  tags = { Name = "${var.vpc_name}-public-${count.index + 1}" }
}

resource "aws_subnet" "private" {
  count = var.create_private_subnets ? length(var.azs) : 0
  vpc_id = aws_vpc.main.id
  cidr_block = var.private_subnets[count.index]
  availability_zone = var.azs[count.index]
  tags = { Name = "${var.vpc_name}-private-${count.index + 1}" }
}
