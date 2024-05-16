# AWS Region
variable "aws_region" {
  type = string
  default = "dummy"
}

# Environment
variable "environment" {
  type = string
  default = "dummy"
}

# VPC's
variable "vpc_app" {
  type = list(string)
  default = ["dummy_1", "dummy_2"]
}

# Subnets
variable "subnet_app" {
  type = list(string)
  default = ["subnet-dummy_1", "subnet-dummy_2"]
}

# Security group
variable "security_group" {
  type = string
  default = "sg-dummy"
}
#--------------------------------------------------------------------
# SECRET DATA
variable "secret_mail_map" {  
  default = {
    "email_from":"refl_api_etl_prices_dev@precia.co",
    "email_to":"dummy@precia.co",
    "password":"dummy",
    "port":"0000","server":"dummy.amazonaws.com",
    "user":"dummy"
  }
  type = map(string)
  sensitive = true
}

variable "secret_db_map" { 
    default = {
      "username":"dummy",
      "password":"dummy",
      "engine":"mysql",
      "host":"dummy.amazonaws.com",
      "port":0000,
    }  
  type = map(string)
  sensitive = true
}

variable "secret_b2c_map" { 
    default = { 
    "ms_tenant" = "dummy"
    "client_id" = "dummy"
  }  
  type = map(string)
  sensitive = true
}

# KEY del ARN del KMS aws/secretsmanager
variable "secrets_kms_key" {
  type    = string
  default = "dummy"
  sensitive = true
}


variable "waf_name"{
  type = string
  default = "dummy"
}