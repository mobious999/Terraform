# 🚀 VPC Outputs
output "vpc_id" {
  description = "The ID of the created VPC"
  value       = aws_vpc.main.id
}

# 🚀 Public Subnets
output "public_subnet_ids" {
  description = "List of public subnet IDs"
  value       = var.create_public_subnets ? aws_subnet.public[*].id : []
}

output "public_route_table_id" {
  description = "Route table ID for public subnets"
  value       = var.create_public_subnets ? aws_route_table.public[0].id : null
}

output "public_nacl_id" {
  description = "Network ACL ID for public subnets"
  value       = var.create_public_subnets ? aws_network_acl.public_nacl[0].id : null
}

# 🚀 Private Subnets
output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = var.create_private_subnets ? aws_subnet.private[*].id : []
}

output "private_route_table_id" {
  description = "Route table ID for private subnets"
  value       = var.create_private_subnets ? aws_route_table.private[0].id : null
}

output "private_nacl_id" {
  description = "Network ACL ID for private subnets"
  value       = var.create_private_subnets ? aws_network_acl.private_nacl[0].id : null
}

# 🚀 Database Subnets
output "database_subnet_ids" {
  description = "List of database subnet IDs"
  value       = var.create_database_subnets ? aws_subnet.database[*].id : []
}

output "database_route_table_id" {
  description = "Route table ID for database subnets"
  value       = var.create_database_subnets ? aws_route_table.database[0].id : null
}

output "database_nacl_id" {
  description = "Network ACL ID for database subnets"
  value       = var.create_database_subnets ? aws_network_acl.database_nacl[0].id : null
}

# 🚀 Cache Subnets
output "cache_subnet_ids" {
  description = "List of cache subnet IDs"
  value       = var.create_cache_subnets ? aws_subnet.cache[*].id : []
}

output "cache_route_table_id" {
  description = "Route table ID for cache subnets"
  value       = var.create_cache_subnets ? aws_route_table.cache[0].id : null
}

output "cache_nacl_id" {
  description = "Network ACL ID for cache subnets"
  value       = var.create_cache_subnets ? aws_network_acl.cache_nacl[0].id : null
}

# 🚀 VPC Endpoints
output "vpc_endpoint_ids" {
  description = "List of VPC endpoint IDs"
  value       = var.enable_vpc_endpoints ? [for vpce in aws_vpc_endpoint.endpoints : vpce.id] : []
}

# 🚀 Security Groups
output "vpc_endpoint_sg_ids" {
  description = "List of Security Group IDs for VPC endpoints"
  value       = var.create_security_groups ? aws_security_group.vpc_endpoint_sg[*].id : var.vpc_endpoint_sg_ids
}

# 🚀 Transit Gateway Outputs
output "tgw_id" {
  description = "Transit Gateway ID"
  value       = var.enable_tgw ? aws_ec2_transit_gateway.tgw[0].id : null
}

output "tgw_attachment_id" {
  description = "Transit Gateway Attachment ID"
  value       = var.enable_tgw ? aws_ec2_transit_gateway_vpc_attachment.tgw_attachment[0].id : null
}

# 🚀 VPC Flow Logs Output
output "flow_log_id" {
  description = "VPC Flow Log ID"
  value       = var.enable_vpc_flow_logs ? aws_flow_log.vpc_flow_log[0].id : null
}
