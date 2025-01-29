variable "vpc_name" { type = string }
variable "vpc_cidr" { type = string }
variable "region" { type = string }
variable "azs" { type = list(string) }

variable "create_public_subnets" { type = bool }
variable "create_private_subnets" { type = bool }
variable "create_database_subnets" { type = bool }
variable "create_cache_subnets" { type = bool }

variable "public_subnets" { type = list(string) }
variable "private_subnets" { type = list(string) }
variable "database_subnets" { type = list(string) }
variable "cache_subnets" { type = list(string) }

variable "enable_vpc_endpoints" { type = bool }
variable "vpc_endpoint_services" { type = list(string) }
