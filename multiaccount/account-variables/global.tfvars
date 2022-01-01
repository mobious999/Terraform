# variable file for all accounts
region = "us-east-2"
customer_identifier_prefix = "someco"
account_ids = ["12345678910", "12345678910", "12345678910", "12345678910", "12345678910", "12345678910", "12345678910", "12345678910", "12345678910", "12345678910", "12345678910", "12345678910", "12345678910"]

account_map = {
  Accountname1 = "12345678910"
  Accountname2 = "12345678910"
  Accountname3 = "12345678910"
  Accountname4 = "12345678910"
  Accountname5 = "12345678910"
  Accountname6 = "12345678910"
  Accountname7 = "12345678910"
  Accountname8 = "12345678910"
  Accountname9 = "12345678910"
  Accountname10 = "12345678910"
}

// Equivalent of global_tags
tags = {
  terraform   = "true"
  "wfl:Email" = "someemail@someco.com"
}
config_delivery_frequency = "Twelve_Hours"

account_emails = {
  Accountname1 = "someemail@someco.com"
  Accountname2 = "someemail@someco.com"
  Accountname3 = "someemail@someco.com"
  Accountname4 = "someemail@someco.com"
  Accountname5 = "someemail@someco.com"
  Accountname6 = "someemail@someco.com"
  Accountname7 = "someemail@someco.com"
  Accountname8 = "someemail@someco.com"
  Accountname9 = "someemail@someco.com"
  Accountname10 = "someemail@someco.com"
}

dev_support_email = "dev@someco.com"
qa_support_email = "qa@someco.com"
uat_support_email = "uat@someco.com"
production_support_email = "prod@someco.com"
cybersecurity_team_email = "security@someco.com"
