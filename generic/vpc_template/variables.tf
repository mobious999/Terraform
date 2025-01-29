# 🚀 General VPC Configuration
variable "vpc_name" {
  description = "The name of the VPC"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
}

# 🚀 Optional Subnet Creation Flags
variable "create_public_subnets" {
  description = "Enable or disable public subnets"
  type        = bool
  default     = true
}

variable "create_private_subnets" {
  description = "Enable or disable private subnets"
  type        = bool
  default     = true
}

variable "create_database_subnets" {
  description = "Enable or disable database subnets"
  type        = bool
  default     = false
}

variable "create_cache_subnets" {
  description = "Enable or disable cache subnets"
  type        = bool
  default     = false
}

# 🚀 Subnet CIDR Blocks
variable "public_subnets" {
  description = "List of CIDR blocks for public subnets"
  type        = list(string)
  default     = []
}

variable "private_subnets" {
  description = "List of CIDR blocks for private subnets"
  type        = list(string)
  default     = []
}

variable "database_subnets" {
  description = "List of CIDR blocks for database subnets"
  type        = list(string)
  default     = []
}

variable "cache_subnets" {
  description = "List of CIDR blocks for cache subnets"
  type        = list(string)
  default     = []
}

# 🚀 Availability Zones
variable "azs" {
  description = "List of availability zones"
  type        = list(string)
}

# 🚀 Transit Gateway Configuration
variable "enable_tgw" {
  description = "Enable Transit Gateway (TGW)"
  type        = bool
  default     = false
}

variable "tgw_asn" {
  description = "ASN for Transit Gateway"
  type        = number
  default     = 64512
}

# 🚀 VPC Flow Logs Configuration
variable "enable_vpc_flow_logs" {
  description = "Enable VPC flow logs"
  type        = bool
  default     = false
}

variable "flow_logs_retention" {
  description = "Retention period for VPC Flow Logs in CloudWatch"
  type        = number
  default     = 30
}

# 🚀 VPC Endpoint Configuration
variable "enable_vpc_endpoints" {
  description = "Enable VPC endpoints"
  type        = bool
  default     = false
}

variable "vpc_endpoint_services" {
  description = "List of VPC endpoint services to enable"
  type        = list(string)
  default     = []
}

variable "vpc_endpoint_types" {
  description = "Mapping of VPC endpoints to types (Interface or Gateway)"
  type        = map(string)
  default     = {}
}

variable "vpc_endpoint_subnet_types" {
  description = "Mapping of VPC endpoints to the subnet type where they should be deployed"
  type        = map(string)
  default     = {}
}

# 🚀 Security Group Configuration
variable "create_security_groups" {
  description = "Enable creation of Security Groups for VPC Endpoints"
  type        = bool
  default     = true
}

variable "vpc_endpoint_sg_ids" {
  description = "List of security group IDs to associate with VPC endpoints. Required if create_security_groups=false."
  type        = list(string)
  default     = []
}

# 🚀 Availability Zones (Scalable)
variable "azs" {
  description = "List of availability zones. This scales the number of subnets automatically."
  type        = list(string)
}

# 🚀 Subnet CIDR Blocks (Dynamically Adjusted to Match AZs)
variable "public_subnets" {
  description = "List of CIDR blocks for public subnets, automatically generated based on AZ count"
  type        = list(string)
}

variable "private_subnets" {
  description = "List of CIDR blocks for private subnets, automatically generated based on AZ count"
  type        = list(string)
}

variable "database_subnets" {
  description = "List of CIDR blocks for database subnets, automatically generated based on AZ count"
  type        = list(string)
}

variable "cache_subnets" {
  description = "List of CIDR blocks for cache subnets, automatically generated based on AZ count"
  type        = list(string)
}