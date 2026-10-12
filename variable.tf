variable "aws_region" {
  description = "AWS region for the API and its resources."
  type        = string
  default     = "us-east-1"
}

variable "dynamodb_table_name" {
  description = "DynamoDB table used for authentication data."
  type        = string
  default     = "fastapi-users"
}

variable "jwt_secret_key" {
  description = "Secret used to sign JWTs. Terraform state must be stored securely."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.jwt_secret_key) >= 32
    error_message = "jwt_secret_key must be at least 32 characters long."
  }
}

variable "github_repo_url" {
  description = "HTTPS Git URL containing the FastAPI application."
  type        = string
  default     = "https://github.com/aboudgrt-ship-it/cloud_project-2.git"
}

variable "app_branch" {
  description = "Git branch to deploy on the EC2 instance."
  type        = string
  default     = "main"
}

variable "instance_type" {
  description = "EC2 instance type for the API."
  type        = string
  default     = "t3.micro"
}

variable "api_ingress_cidrs" {
  description = "IPv4 CIDRs allowed to reach the API. Use a trusted client range."
  type        = list(string)
}

variable "vpc_cidr" {
  description = "CIDR block for the API VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public API subnet."
  type        = string
  default     = "10.0.1.0/24"
}

variable "cloudwatch_namespace" {
  description = "CloudWatch metrics namespace for the API."
  type        = string
  default     = "FastAPIAuth"
}
