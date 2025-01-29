module "vpc" {
  source             = "./modules/vpc"
  vpc_name           = "my-vpc"
  vpc_cidr           = "10.0.0.0/16"
  region             = "us-east-1"

  # 🚀 Availability Zones (Automatically Scales!)
  azs = ["us-east-1a", "us-east-1b", "us-east-1c", "us-east-1d"]

  # 🚀 Subnet Configurations (Dynamically Scales for AZ Count)
  create_public_subnets  = true
  create_private_subnets = true
  create_database_subnets = true
  create_cache_subnets = true

  public_subnets   = [for i in range(length(var.azs)) : "10.0.${i + 1}.0/24"]
  private_subnets  = [for i in range(length(var.azs)) : "10.0.${i + length(var.azs) + 1}.0/24"]
  database_subnets = [for i in range(length(var.azs)) : "10.0.${i + 2 * length(var.azs) + 1}.0/24"]
  cache_subnets    = [for i in range(length(var.azs)) : "10.0.${i + 3 * length(var.azs) + 1}.0/24"]

  # 🚀 VPC Endpoints Configuration
  enable_vpc_endpoints = true
  vpc_endpoint_services = ["s3", "dynamodb", "ec2", "ssm", "secretsmanager"]

  vpc_endpoint_types = {
    "s3"             = "Gateway"
    "dynamodb"       = "Gateway"
    "ec2"            = "Interface"
    "ssm"            = "Interface"
    "secretsmanager" = "Interface"
  }

  vpc_endpoint_subnet_types = {
    "s3"             = "private"
    "dynamodb"       = "private"
    "ec2"            = "private"
    "ssm"            = "private"
    "secretsmanager" = "private"
  }

  # 🚀 Security Group Configuration (Supports both dynamic creation and predefined SGs)
  create_security_groups = true
  vpc_endpoint_sg_ids    = []

  # 🚀 Transit Gateway Configuration
  enable_tgw       = true
  tgw_asn          = 64512

  # 🚀 VPC Flow Logs
  enable_vpc_flow_logs = true
  flow_logs_retention  = 30
}
