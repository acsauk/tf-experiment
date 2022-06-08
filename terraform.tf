locals {
  sandbox = "995199299616"
}

provider "aws" {
  region = "eu-west-1"

  assume_role {
    role_arn     = "arn:aws:iam::${local.sandbox}:role/operator"
    session_name = "terraform-session"
  }
}
