import os
import time
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

import jwt
from botocore.exceptions import ClientError
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt import InvalidTokenError
from jwt.exceptions import PyJWTError
from pydantic import BaseModel, ConfigDict, Field

from configuration import Authenticator, DynamoDBUserRepository, UserAlreadyExistsError


class Settings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    secret_key: str = Field(
        default_factory=lambda: os.getenv("JWT_SECRET_KEY", "development-secret-change-me-32-bytes"),
        min_length=32,
    )
    algorithm: str = "HS256"
    access_token_expire_minutes: int = Field(default_factory=lambda: int(os.getenv("JWT_ACCESS_MINUTES", "15")))
    refresh_token_expire_days: int = Field(default_factory=lambda: int(os.getenv("JWT_REFRESH_DAYS", "30")))
    cookie_secure: bool = Field(default_factory=lambda: os.getenv("COOKIE_SECURE", "false").lower() == "true")
    access_cookie_name: str = "access_token"
    refresh_cookie_name: str = "refresh_token"


settings = Settings()
SECRET_KEY = settings.secret_key
ALGORITHM = settings.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes
REFRESH_TOKEN_EXPIRE_DAYS = settings.refresh_token_expire_days
COOKIE_SECURE = settings.cookie_secure
ACCESS_COOKIE_NAME = settings.access_cookie_name
REFRESH_COOKIE_NAME = settings.refresh_cookie_name

user_repo = DynamoDBUserRepository()
authenticator = Authenticator(user_repo)
app = FastAPI(title="Auth API")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token", auto_error=False)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=8)


class UserOut(BaseModel):
    username: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: str


def create_token(username: str, token_use: str, lifetime: timedelta) -> str:
    expires_at = datetime.now(timezone.utc) + lifetime
    payload = {"sub": username, "token_use": token_use, "exp": expires_at}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(username: str) -> str:
    return create_token(username, "access", timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))


def create_refresh_token(username: str) -> str:
    return create_token(username, "refresh", timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))


def set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    response.set_cookie(
        key=ACCESS_COOKIE_NAME,
        value=access_token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


def decode_token(token: str, expected_use: str) -> str:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except (PyJWTError, InvalidTokenError) as error:
        raise unauthorized from error

    username = payload.get("sub")
    if not isinstance(username, str) or payload.get("token_use") != expected_use:
        raise unauthorized
    return username


def get_current_user(
    bearer_token: Annotated[Optional[str], Depends(oauth2_scheme)] = None,
    access_cookie: Annotated[Optional[str], Cookie(alias=ACCESS_COOKIE_NAME)] = None,
) -> dict:
    token = bearer_token or access_cookie
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = decode_token(token, "access")
    user_data = user_repo.get_user_data(username)
    if user_data is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user_data


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = time.perf_counter() - start_time
    response.headers["X-Process-Time"] = str(process_time)

    monitoring = getattr(request.app.state, "monitoring", None)
    if monitoring is not None:
        monitoring.safely_record("HttpRequests")
        monitoring.safely_write_log(
            f"{request.method} {request.url.path} returned {response.status_code}"
        )

    return response


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate) -> UserOut:
    try:
        authenticator.create_user(user.username, user.password)
    except UserAlreadyExistsError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists") from error
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)) from error
    except ClientError as error:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable") from error
    return UserOut(username=user.username.strip())


@app.post("/token", response_model=Token)
def login(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    try:
        authenticated, message = authenticator.authenticate(form_data.username, form_data.password)
    except ClientError as error:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable") from error

    if not authenticated:
        error_status = (
            status.HTTP_403_FORBIDDEN if "locked" in message.lower() else status.HTTP_401_UNAUTHORIZED
        )
        raise HTTPException(
            status_code=error_status,
            detail=message,
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(form_data.username)
    refresh_token = create_refresh_token(form_data.username)
    set_auth_cookies(response, access_token, refresh_token)
    return Token(access_token=access_token, refresh_token=refresh_token)


@app.post("/refresh", response_model=Token)
def refresh_tokens(
    response: Response,
    refresh_cookie: Annotated[Optional[str], Cookie(alias=REFRESH_COOKIE_NAME)] = None,
) -> Token:
    if refresh_cookie is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token required")

    username = decode_token(refresh_cookie, "refresh")
    if user_repo.get_user_data(username) is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    access_token = create_access_token(username)
    refresh_token = create_refresh_token(username)
    set_auth_cookies(response, access_token, refresh_token)
    return Token(access_token=access_token, refresh_token=refresh_token)


@app.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response) -> Response:
    response.delete_cookie(
        key=ACCESS_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
    )
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@app.get("/user", response_model=UserOut)
def read_user_me(current_user: Annotated[dict, Depends(get_current_user)]) -> UserOut:
    return UserOut(username=current_user["username"])


@app.get("/items")
def read_items(
    session_id: Annotated[Optional[str], Cookie()] = None,
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict:
    return {
        "session_id": session_id,
        "authorization_present": authorization is not None,
    }
