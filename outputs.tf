output "api_url" {
  description = "HTTP URL for the FastAPI application."
  value       = "http://${aws_instance.fastapi.public_ip}:8000"
}

output "instance_public_ip" {
  description = "Public IP address of the FastAPI EC2 instance."
  value       = aws_instance.fastapi.public_ip
}

output "vpc_id" {
  description = "ID of the API VPC."
  value       = aws_vpc.main.id
}

output "dynamodb_table_name" {
  description = "Name of the authentication data table."
  value       = aws_dynamodb_table.users.name
}

output "jwt_secret_arn" {
  description = "ARN of the JWT signing secret."
  value       = aws_secretsmanager_secret.jwt.arn
}
