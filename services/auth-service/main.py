from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from passlib.context import CryptContext
import jwt
import uuid
import os

app = FastAPI(
    title="Banking Auth Service",
    description="Secure Authentication API - DevSecOps Project",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

fake_users_db = {}

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    created_at: str

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_token(data: dict, expires_delta: timedelta) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + expires_delta
    payload["jti"] = str(uuid.uuid4())
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_token(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id or user_id not in fake_users_db:
        raise HTTPException(status_code=401, detail="User not found")
    return fake_users_db[user_id]

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "auth-service", "timestamp": datetime.utcnow().isoformat()}

@app.post("/api/v1/auth/register", response_model=UserResponse, status_code=201)
def register(user: UserRegister):
    for u in fake_users_db.values():
        if u["email"] == user.email:
            raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    fake_users_db[user_id] = {
        "id": user_id,
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": hash_password(user.password),
        "created_at": datetime.utcnow().isoformat(),
    }
    return UserResponse(id=user_id, email=user.email, full_name=user.full_name, created_at=fake_users_db[user_id]["created_at"])

@app.post("/api/v1/auth/login", response_model=TokenResponse)
def login(credentials: UserLogin):
    user = None
    for u in fake_users_db.values():
        if u["email"] == credentials.email:
            user = u
            break
    if not user or not verify_password(credentials.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_token({"sub": user["id"], "email": user["email"], "type": "access"}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_token({"sub": user["id"], "type": "refresh"}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)

@app.get("/api/v1/auth/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(id=current_user["id"], email=current_user["email"], full_name=current_user["full_name"], created_at=current_user["created_at"])
