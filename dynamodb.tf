resource "aws_dynamodb_table" "users" {
  name         = var.dynamodb_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "username"

  attribute {
    name = "username"
    type = "S"
  }

  tags = {
    Name        = var.dynamodb_table_name
    Application = "fastapi-auth"
  }
}

resource "aws_secretsmanager_secret" "jwt" {
  name                    = "fastapi-auth/jwt-signing-key"
  description             = "JWT signing key used by the FastAPI authentication service."
  recovery_window_in_days = 7

  tags = {
    Application = "fastapi-auth"
  }
}

resource "aws_secretsmanager_secret_version" "jwt" {
  secret_id     = aws_secretsmanager_secret.jwt.id
  secret_string = var.jwt_secret_key
}
