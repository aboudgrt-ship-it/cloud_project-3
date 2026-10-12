import importlib
import os
import time
import unittest
from unittest.mock import Mock, patch

import bcrypt
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from configuration import Authenticator, DynamoDBUserRepository, UserAlreadyExistsError


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch("boto3.resource") as mock_resource:
            mock_resource.return_value.Table.return_value = Mock()
            cls.api = importlib.import_module("FastApi")
        cls.api.SECRET_KEY = "test-secret-key-with-at-least-32-bytes"

    def setUp(self):
        self.repository = Mock()
        self.authenticator = Authenticator(self.repository)
        self.monitoring = Mock()
        self.api.user_repo = self.repository
        self.api.authenticator = self.authenticator
        self.api.app.state.monitoring = self.monitoring
        self.client = TestClient(self.api.app)

    def test_health_endpoint_includes_process_time_and_cloudwatch_metrics(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
        self.assertIn("X-Process-Time", response.headers)
        self.monitoring.safely_record.assert_called_once_with("HttpRequests")
        self.monitoring.safely_write_log.assert_called_once_with(
            "GET /health returned 200"
        )

    def test_registration_creates_user_in_dynamodb(self):
        response = self.client.post(
            "/register",
            json={"username": "alice", "password": "correct-password"},
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json(), {"username": "alice"})
        args = self.repository.save_user.call_args.args
        self.assertEqual(args[0], "alice")
        self.assertTrue(
            bcrypt.checkpw("correct-password".encode("utf-8"), args[1])
        )

    def test_registration_rejects_duplicate_username(self):
        self.repository.save_user.side_effect = UserAlreadyExistsError("alice")

        response = self.client.post(
            "/register",
            json={"username": "alice", "password": "correct-password"},
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"], "Username already exists")
        self.repository.save_user.assert_called_once()

    def test_login_returns_tokens_and_sets_http_only_cookies(self):
        password_hash = Authenticator.hash_password("correct-password")
        self.repository.get_user_data.return_value = {
            "username": "alice",
            "password_hash": password_hash.decode("utf-8"),
            "failed_attempts": 0,
            "lockout_until": 0,
        }

        response = self.client.post(
            "/token",
            data={"username": "alice", "password": "correct-password"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["token_type"], "bearer")
        self.assertTrue(payload["access_token"])
        self.assertTrue(payload["refresh_token"])
        self.assertIn("httponly", response.headers["set-cookie"].lower())
        self.repository.reset_failed_attempts.assert_called_once_with("alice")

    def test_failed_login_returns_unauthorized(self):
        self.repository.get_user_data.return_value = {
            "username": "alice",
            "password_hash": Authenticator.hash_password("correct-password").decode(
                "utf-8"
            ),
            "failed_attempts": 0,
            "lockout_until": 0,
        }
        self.repository.increment_failed_attempts.return_value = 1

        response = self.client.post(
            "/token",
            data={"username": "alice", "password": "wrong-password"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Invalid username or password.")
        self.repository.increment_failed_attempts.assert_called_once_with("alice")

    def test_locked_account_returns_forbidden(self):
        self.repository.get_user_data.return_value = {
            "username": "alice",
            "password_hash": Authenticator.hash_password("correct-password").decode(
                "utf-8"
            ),
            "failed_attempts": 5,
            "lockout_until": int(time.time()) + 900,
        }

        response = self.client.post(
            "/token",
            data={"username": "alice", "password": "wrong-password"},
        )

        self.assertEqual(response.status_code, 403)

    def test_database_failure_returns_service_unavailable(self):
        self.repository.get_user_data.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError"}}, "GetItem"
        )

        response = self.client.post(
            "/token",
            data={"username": "alice", "password": "correct-password"},
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"], "Database unavailable")

    def test_protected_endpoint_requires_jwt(self):
        response = self.client.get("/user")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["www-authenticate"], "Bearer")

    def test_protected_endpoint_reads_user_from_dynamodb(self):
        self.repository.get_user_data.return_value = {"username": "alice"}
        token = self.api.create_access_token("alice")

        response = self.client.get(
            "/user",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"username": "alice"})
        self.repository.get_user_data.assert_called_once_with("alice")

    def test_refresh_requires_a_refresh_cookie(self):
        response = self.client.post("/refresh")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Refresh token required")

    def test_refresh_rejects_access_token(self):
        self.client.cookies.set(
            self.api.REFRESH_COOKIE_NAME,
            self.api.create_access_token("alice"),
        )

        response = self.client.post("/refresh")

        self.assertEqual(response.status_code, 401)


class DynamoDBRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.repository = DynamoDBUserRepository.__new__(DynamoDBUserRepository)
        self.repository.table = Mock()

    def test_save_user_does_not_overwrite_existing_user(self):
        self.repository.save_user("alice", b"hashed-password")

        call = self.repository.table.put_item.call_args.kwargs
        self.assertEqual(call["ConditionExpression"], "attribute_not_exists(username)")
        self.assertEqual(call["Item"]["username"], "alice")

    def test_reset_failed_attempts_uses_valid_dynamodb_arguments(self):
        self.repository.reset_failed_attempts("alice")

        call = self.repository.table.update_item.call_args.kwargs
        self.assertEqual(
            call["ExpressionAttributeValues"],
            {":zero": 0},
        )


class ApplicationStartupTests(unittest.TestCase):
    def test_main_module_import_does_not_call_aws(self):
        with patch("boto3.client") as aws_client:
            main_module = importlib.import_module("main")

        self.assertTrue(callable(main_module.create_application))
        aws_client.assert_not_called()

    def test_jwt_secret_is_loaded_from_secrets_manager(self):
        secret = "test-secret-key-with-at-least-32-bytes"
        with patch.dict(
            os.environ,
            {"JWT_SECRET_ARN": "arn:aws:secretsmanager:region:account:secret:key"},
        ), patch("main.boto3.client") as client_factory:
            client_factory.return_value.get_secret_value.return_value = {
                "SecretString": secret
            }

            result = importlib.import_module("main").load_jwt_secret()

        self.assertEqual(result, secret)
        client_factory.return_value.get_secret_value.assert_called_once_with(
            SecretId="arn:aws:secretsmanager:region:account:secret:key"
        )

    def test_application_attaches_cloudwatch_monitoring(self):
        main_module = importlib.import_module("main")
        with patch.dict(os.environ, {"JWT_SECRET_ARN": ""}), patch(
            "cloudwatch.CloudWatchIntegration"
        ) as monitoring_factory:
            application = main_module.create_application()

        self.assertIs(application, self.api_app())
        self.assertIs(
            application.state.monitoring,
            monitoring_factory.return_value,
        )

    @staticmethod
    def api_app():
        return importlib.import_module("FastApi").app


if __name__ == "__main__":
    unittest.main()
