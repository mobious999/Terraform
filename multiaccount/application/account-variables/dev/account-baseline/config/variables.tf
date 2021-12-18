variable "region" {}
variable "profile" {}

variable "tags" {
  type = map(string)
}
variable "customer_identifier_prefix" {}

variable "account_ids" {
  type = list(string)
}

variable "account_map" {
  type = map(string)
}
variable "vpc_name" {}

variable "vpc" {}

variable "vpc_cidr" {}

variable "account_name" {}

variable "config_delivery_frequency" {}

variable "account_emails" {
  type = map(string)
}

variable "cloudtrail_name" {
  default = "medpro-cloudtrail"
}

variable "network_cidr" {}

variable "subscription_emails" {
  type    = list(string)
  default = [
    "DL-CyberSecurityTeam@medpro.com",
    "nash.fleet@cloudreach.com",
    "dl-ccoe@medpro.com"
  ]
}