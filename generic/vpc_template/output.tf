# Exposing VPC ID
output "vpc_id" {
  description = "VPC ID from the module"
  value       = module.vpc.vpc_id
}

# Public Subnets Outputs
output "public_subnet_ids" {
  description = "List of public subnet IDs from module"
  value       = module.vpc.public_subnet_ids
}

output "public_route_table_id" {
  description = "Public Route Table ID"
  value       = module.vpc.public_route_table_id
}

output "public_nacl_id" {
  description = "Public NACL ID"
  value       = module.vpc.public_nacl_id
}

# Private Subnets Outputs
output "private_subnet_ids" {
  description = "List of private subnet IDs from module"
  value       = module.vpc.private_subnet_ids
}

output "private_route_table_id" {
  description = "Private Route Table ID"
  value       = module.vpc.private_route_table_id
}

output "private_nacl_id" {
  description = "Private NACL ID"
  value       = module.vpc.private_nacl_id
}

# Database Subnets Outputs
output "database_subnet_ids" {
  description = "List of database subnet IDs from module"
  value       = module.vpc.database_subnet_ids
}

output "database_route_table_id" {
  description = "Database Route Table ID"
  value       = module.vpc.database_route_table_id
}

output "database_nacl_id" {
  description = "Database NACL ID"
  value       = module.vpc.database_nacl_id
}

# Cache Subnets Outputs
output "cache_subnet_ids" {
  description = "List of cache subnet IDs from module"
  value       = module.vpc.cache_subnet_ids
}

output "cache_route_table_id" {
  description = "Cache Route Table ID"
  value       = module.vpc.cache_route_table_id
}

output "cache_nacl_id" {
  description = "Cache NACL ID"
  value       = module.vpc.cache_nacl_id
}

# Transit Gateway Outputs
output "tgw_id" {
  description = "Transit Gateway ID"
  value       = module.vpc.tgw_id
}

output "tgw_attachment_id" {
  description = "Transit Gateway Attachment ID"
  value       = module.vpc.tgw_attachment_id
}

# VPC Flow Logs Output
output "flow_log_id" {
  description = "VPC Flow Log ID"
  value       = module.vpc.flow_log_id
}
