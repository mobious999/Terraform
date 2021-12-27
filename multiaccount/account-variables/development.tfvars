profile = "Development"
account_name = "Development"
vpc_name = "Development"
vpc_cidr = "10.0.0.0/16"

#define the subnets to be used by the 
vpc = {
  azs = ["us-east-2a", "us-east-2b","us-east-2c","us-east-2d"]
  private_subnets     = ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24","10.0.3.0/24",]
  public_subnets      = ["10.1.0.0/24", "10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24"]
  database_subnets    = ["10.2.0.0/24", "10.2.1.0/24", "10.2.2.0/24", "10.2.3.0/24"]
  elasticache_subnets = ["10.3.0.0/24", "10.3.1.0/24", "10.3.2.0/24", "10.3.3.0/24"]
  redshift_subnets    = ["10.4.0.0/24", "10.4.1.0/24", "10.4.2.0/24", "10.4.3.0/24"]
  intra_subnets       = ["10.5.0.0/24", "10.5.1.0/24", "10.5.2.0/24", "10.5.3.0/24"]
}

ingress_cidr_blocks = ""
ingress_cidr_blocks_generic = ""
ingress_cidr_blocks_web = ""
ingress_cidr_blocks_other = ""
egress_cidr_blocks = "0.0.0.0/0"

#used for the default bucket name for all of the state files
statebucketname = "develpment_s3"

#default tags that can be merged into any terraform file

Development_tags = {
  "Environment" = "dev"
}

Development_windows_os_tags = {
  "Os" = "Windows"
  "Patchgroup" = "Windows"
  "Ssm" = "True"
  "Teamemail" "someuser@someco.com"
}

Development_linux_os_tags = {
  "Os" = "Linux"
  "Patchgroup" = "Linux"
  "Ssm" = "True"
  "Teamemail" "someuser@someco.com"
}

