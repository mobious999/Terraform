profile = "profileforaccess"
account_name = "Development"
vpc_name = "Development"
vpc_cidr = "10.20.48.0/20"

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