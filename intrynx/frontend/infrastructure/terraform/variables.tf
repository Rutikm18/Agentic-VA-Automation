variable "aws_region"       { type = string; default = "us-east-1" }
variable "cluster_name"     { type = string; default = "adversa-prod" }
variable "environment"      { type = string; default = "production" }
variable "vpc_cidr"         { type = string; default = "10.200.0.0/16" }
variable "instance_type"    { type = string; default = "t3.xlarge" }
variable "min_nodes"        { type = number; default = 3 }
variable "max_nodes"        { type = number; default = 12 }
variable "desired_nodes"    { type = number; default = 3 }
variable "db_instance_class"{ type = string; default = "db.t3.large" }
variable "db_name"          { type = string; default = "adversa" }
variable "db_username"      { type = string; default = "adversa"; sensitive = true }
variable "db_password"      { type = string; sensitive = true }
variable "kafka_broker_count" { type = number; default = 3 }
variable "artifacts_bucket" { type = string; default = "adversa-artifacts" }
