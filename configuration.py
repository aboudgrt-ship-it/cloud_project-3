import os
import time
from typing import Optional, Tuple

import bcrypt
import boto3
from botocore.exceptions import ClientError

MAX_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 900


class UserAlreadyExistsError(Exception):
    """Raised when attempting to register an existing username."""


class DynamoDBUserRepository:
    """Store and retrieve user authentication data in DynamoDB."""

    def __init__(
        self,
        table_name: Optional[str] = None,
        region_name: Optional[str] = None,
    ) -> None:
        table_name = table_name or os.getenv("DYNAMODB_TABLE", "users")
        region_name = region_name or os.getenv("AWS_REGION", "us-east-1")
        dynamodb = boto3.resource("dynamodb", region_name=region_name)
        self.table = dynamodb.Table(table_name)

    def save_user(self, username: str, password_hash: bytes) -> None:
        """Create a user, rejecting duplicate usernames atomically."""
        try:
            self.table.put_item(
                Item={
                    "username": username,
                    "password_hash": password_hash.decode("utf-8"),
                    "failed_attempts": 0,
                    "lockout_until": 0,
                },
                ConditionExpression="attribute_not_exists(username)",
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise UserAlreadyExistsError(username) from error
            raise

    def get_user_data(self, username: str) -> Optional[dict]:
        """Fetch all user data from DynamoDB."""
        response = self.table.get_item(Key={"username": username})
        return response.get("Item")

    def increment_failed_attempts(self, username: str) -> int:
        """Increment failed attempts and set a lockout at the threshold."""
        response = self.table.update_item(
            Key={"username": username},
            UpdateExpression="SET failed_attempts = failed_attempts + :inc",
            ExpressionAttributeValues={":inc": 1},
            ReturnValues="UPDATED_NEW",
        )
        attempts = int(response["Attributes"]["failed_attempts"])

        if attempts >= MAX_ATTEMPTS:
            lockout_time = int(time.time()) + LOCKOUT_DURATION_SECONDS
            self.table.update_item(
                Key={"username": username},
                UpdateExpression="SET lockout_until = :lt",
                ExpressionAttributeValues={":lt": lockout_time},
            )
        return attempts

    def reset_failed_attempts(self, username: str) -> None:
        """Reset failed attempts and lockout after successful authentication."""
        self.table.update_item(
            Key={"username": username},
            UpdateExpression="SET failed_attempts = :zero, lockout_until = :zero",
            ExpressionAttributeValues={":zero": 0},
        )


class Authenticator:
    """Handle user registration and secure password verification."""

    def __init__(self, user_repository: DynamoDBUserRepository) -> None:
        self.user_repository = user_repository

    def create_user(self, username: str, password: str) -> None:
        """Validate input and hash the password before saving it."""
        username = username.strip()
        if not username or not password:
            raise ValueError("Username and password cannot be empty.")
        if len(password.encode("utf-8")) > 72:
            raise ValueError("Password must be no more than 72 UTF-8 bytes.")

        password_hash = self.hash_password(password)
        self.user_repository.save_user(username, password_hash)

    @staticmethod
    def hash_password(password: str) -> bytes:
        """Return a bcrypt password hash."""
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    def authenticate(self, username: str, password: str) -> Tuple[bool, str]:
        """Authenticate a user and enforce the failed-login lockout policy."""
        user_data = self.user_repository.get_user_data(username)
        if not user_data:
            return False, "Invalid username or password."

        current_time = int(time.time())
        lockout_until = int(user_data.get("lockout_until", 0))
        if lockout_until > current_time:
            wait_time = (lockout_until - current_time) // 60
            return False, f"Account locked. Try again in {max(1, wait_time)} minutes."

        stored_hash = user_data.get("password_hash", "").encode("utf-8")
        try:
            password_matches = bcrypt.checkpw(password.encode("utf-8"), stored_hash)
        except (ValueError, TypeError):
            password_matches = False

        if password_matches:
            self.user_repository.reset_failed_attempts(username)
            return True, "Login successful."

        attempts = self.user_repository.increment_failed_attempts(username)
        if attempts >= MAX_ATTEMPTS:
            return False, (
                "Too many failed attempts. Account locked for "
                f"{LOCKOUT_DURATION_SECONDS // 60} minutes."
            )
        return False, "Invalid username or password."

    def get_user_profile(self, username: str) -> Optional[dict]:
        """Return non-sensitive user data."""
        user_data = self.user_repository.get_user_data(username)
        if not user_data:
            return None
        return {"username": user_data.get("username")}


def main() -> None:
    repository = DynamoDBUserRepository()
    authenticator = Authenticator(repository)
    action = input("Choose action (register/login): ").strip().lower()
    username = input("Username: ").strip()

    if action == "register":
        password = input("Password: ")
        try:
            authenticator.create_user(username, password)
            print("User registered successfully.")
        except UserAlreadyExistsError:
            print("Username already exists.")
        except (ValueError, ClientError) as error:
            print(f"Error: {error}")
    elif action == "login":
        password = input("Password: ")
        try:
            _, message = authenticator.authenticate(username, password)
            print(message)
        except ClientError as error:
            print(f"Database error: {error.response['Error']['Code']}")
    else:
        print("Invalid action.")


if __name__ == "__main__":
    main()
