# AWS Terraform baseline scaffolding — VPC + subnet.
# Clean by design. Findings are introduced via pull requests.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

variable "internal_admin_cidr" {
  description = "CIDR block permitted to reach administrative ports."
  type        = string
  default     = "10.0.0.0/16"
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name    = "guardrails-lab-vpc"
    project = "guardrails-lab"
    owner   = "platform-lab"
  }
}

resource "aws_subnet" "lab" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-west-2a"

  tags = {
    Name = "guardrails-lab-subnet"
  }
}
