from fastapi import FastAPI, Depends, HTTPException, status, Cookie, Header , APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm 
from datetime import datetime, timedelta, timezone
import jwt
import bcrypt
from jwt.exceptions import PyJWTError
import os 
from pydantic import BaseModel, EmailStr
from typing import Any, Optional, Annotated  

# --- 1. Settings and Configuration ---
# Secret key to encode the token (should be changed in production)
SECRET_KEY = os.getenv("SECRET_KEY", "development-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15


# Define the path to obtain the token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Mock database for testing (in reality, a real database is used)
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": bcrypt.hashpw(b"secret123", bcrypt.gensalt()).decode('utf-8'),
    }
}

items = {"foo": "the wrestless"}

# --- 2. Data Models ---
class Token(BaseModel): 
    access_token: str
    token_type: str

class UserIn(BaseModel):
    username: str
    password: str
    email: EmailStr
    full_name: Optional[str] = None

class UserOut(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None

# --- 3. Helper Functions ---
def password_hasher(password: str) -> str:
    """Encrypt password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8') 

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check if the entered password matches the hashed one"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def authenticate_user(username: str, password: str):
    """Authenticate user and verify credentials"""
    user = fake_users_db.get(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT token with an expiration time"""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- 4. Dependencies ---
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """Function to verify the token and extract current user data"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except PyJWTError:
        raise credentials_exception
    
    user = fake_users_db.get(username)
    if user is None:
        raise credentials_exception
    return user

# --- 5. API Routes ---

app = FastAPI()

router = APIRouter(
    prefix="/users",
    tags=["users"],
)

@router.get("/profile")
async def read_user_profile(current_user: Annotated[dict, Depends(get_current_user)]):
    return {"message": "this is your profile", "user": current_user["username"]}

app.include_router(router)

@app.post("/token", response_model=Token)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """Login route to obtain the token"""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/user", response_model=UserOut)
async def read_user_me(current_user: Annotated[dict, Depends(get_current_user)]):
    """Return the currently logged-in user data"""
    return current_user

@app.get("/items")
async def read_items(
    # Extract Cookies
    session_id: Annotated[Optional[str], Cookie()] = None,
    # Extract Headers
    user_agent: Annotated[Optional[str], Header()] = None,
    host: Annotated[Optional[str], Header()] = None,
):
    """Display cookies and headers sent in the request"""
    return {
        "cookies": {"session_id": session_id},
        "headers": {"user_agent": user_agent, "host": host}
    }

@app.post("/token/refresh")
async def refresh_token(current_user: Annotated[dict, Depends(get_current_user)]):
    """Refresh token for an already logged-in user"""
    new_token = create_access_token(data={"sub": current_user["username"]})
    return {"access_token": new_token, "token_type": "bearer"}