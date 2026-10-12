# FastAPI AWS Authentication API

FastAPI authentication backed by DynamoDB, with JWT signing keys stored in
Secrets Manager and request metrics/logs sent to CloudWatch. Terraform provisions
the VPC, public EC2 instance, DynamoDB table, secret, CloudWatch log group, and
least-privilege instance role.

## Application files

- `FastApi.py` - FastAPI routes, JWT validation, and request telemetry.
- `configuration.py` - DynamoDB repository and bcrypt authentication service.
- `cloudwatch.py` - CloudWatch metrics and log publishing.
- `main.py` - Loads the JWT key through the instance role and starts Uvicorn.
- `test_auth_api.py` - API, DynamoDB contract, and startup tests.
- `*.tf` - AWS infrastructure and EC2 bootstrap configuration.

## Local development

Install dependencies and run the tests:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m unittest test_auth_api
```

Set `JWT_SECRET_KEY` to a unique key containing at least 32 UTF-8 bytes and
configure AWS credentials and a DynamoDB table with a string partition key
named `username`. Then start the API:

```bash
export JWT_SECRET_KEY="replace-with-a-random-secret-of-at-least-32-bytes"
export AWS_REGION=us-east-1
export DYNAMODB_TABLE=fastapi-users
python main.py
```

The API listens on `http://localhost:8000` by default. Login uses OAuth2 form
fields (`username` and `password`), not JSON.

## API endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Health check |
| `POST` | `/register` | Register a user |
| `POST` | `/token` | Authenticate and issue access/refresh tokens |
| `POST` | `/refresh` | Rotate tokens using the HTTP-only refresh cookie |
| `POST` | `/logout` | Clear authentication cookies |
| `GET` | `/user` | Return the authenticated user's public profile |

The access token may be supplied using the Bearer header or the HTTP-only
`access_token` cookie. The refresh token is stored in an HTTP-only
`refresh_token` cookie.

## Terraform deployment

The EC2 bootstrap clones `github_repo_url` at `app_branch`; publish the
application files to that branch before creating the instance. Configure AWS
credentials with permission to create the listed infrastructure, and provide
a strong signing key without putting it in a committed `.tfvars` file:

```bash
export TF_VAR_jwt_secret_key='provide-a-unique-random-value-of-at-least-32-bytes'
export TF_VAR_api_ingress_cidrs='["YOUR_PUBLIC_IP/32"]'
terraform init
terraform fmt -recursive
terraform validate
terraform plan
terraform apply
```

Terraform marks the key sensitive, but the secret version is still stored in
Terraform state. Use encrypted, access-controlled remote state and protect its
backups. The application instance retrieves the key at startup using its
instance role; the key is not embedded in EC2 user data.

Set `api_ingress_cidrs` to trusted client CIDRs before deployment; Terraform
requires the value and does not expose the API to all IPv4 addresses by
default. The example does not configure TLS; use an HTTPS
load-balancer/reverse-proxy setup before sending real credentials over a
network.

The instance role is limited to the configured DynamoDB table, JWT secret,
CloudWatch namespace, and API log group. AWS credentials are provided by the
EC2 instance profile rather than hard-coded access keys.
