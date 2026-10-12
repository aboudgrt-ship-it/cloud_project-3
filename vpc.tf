data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "fastapi-auth"
    Application = "fastapi-auth"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "fastapi-auth"
    Application = "fastapi-auth"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name        = "fastapi-auth-public"
    Application = "fastapi-auth"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name        = "fastapi-auth-public"
    Application = "fastapi-auth"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "fastapi" {
  name        = "fastapi-auth"
  description = "Allow configured clients to reach the FastAPI service."
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "FastAPI HTTP API"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = var.api_ingress_cidrs
  }

  egress {
    description = "Allow outbound access to AWS APIs and package repositories."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "fastapi-auth"
    Application = "fastapi-auth"
  }
}
