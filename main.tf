terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0, < 7.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/fastapi/auth"
  retention_in_days = 30

  tags = {
    Application = "fastapi-auth"
  }
}

resource "aws_iam_role" "fastapi" {
  name = "fastapi-auth-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "fastapi" {
  name = "fastapi-auth-runtime"
  role = aws_iam_role.fastapi.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "UserAuthenticationData"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
        ]
        Resource = aws_dynamodb_table.users.arn
      },
      {
        Sid      = "ReadJwtSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.jwt.arn
      },
      {
        Sid      = "PublishApiMetrics"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = var.cloudwatch_namespace
          }
        }
      },
      {
        Sid    = "WriteApiLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.api.arn}:*"
      },
    ]
  })
}

resource "aws_iam_instance_profile" "fastapi" {
  name = "fastapi-auth-instance-profile"
  role = aws_iam_role.fastapi.name
}

resource "aws_instance" "fastapi" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.fastapi.id]
  iam_instance_profile        = aws_iam_instance_profile.fastapi.name
  associate_public_ip_address = true

  user_data = <<-BOOTSTRAP
    #!/bin/bash
    set -eu
    apt-get update
    apt-get install -y git python3-venv
    git clone --branch ${var.app_branch} ${var.github_repo_url} /opt/fastapi-auth
    python3 -m venv /opt/fastapi-auth/.venv
    /opt/fastapi-auth/.venv/bin/pip install -r /opt/fastapi-auth/requirements.txt
    cat > /etc/systemd/system/fastapi-auth.service <<'SERVICE'
    [Unit]
    Description=FastAPI authentication service
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    WorkingDirectory=/opt/fastapi-auth
    Environment=AWS_REGION=${var.aws_region}
    Environment=DYNAMODB_TABLE=${var.dynamodb_table_name}
    Environment=JWT_SECRET_ARN=${aws_secretsmanager_secret.jwt.arn}
    Environment=CLOUDWATCH_NAMESPACE=${var.cloudwatch_namespace}
    Environment=CLOUDWATCH_LOG_GROUP=${aws_cloudwatch_log_group.api.name}
    Environment=APP_HOST=0.0.0.0
    Environment=APP_PORT=8000
    Environment=COOKIE_SECURE=false
    ExecStart=/opt/fastapi-auth/.venv/bin/python /opt/fastapi-auth/main.py
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target
    SERVICE
    systemctl daemon-reload
    systemctl enable --now fastapi-auth
  BOOTSTRAP

  root_block_device {
    encrypted   = true
    volume_size = 8
    volume_type = "gp3"
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name        = "fastapi-auth"
    Application = "fastapi-auth"
  }
}
