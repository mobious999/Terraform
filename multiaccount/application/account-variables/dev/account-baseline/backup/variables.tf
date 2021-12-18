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
