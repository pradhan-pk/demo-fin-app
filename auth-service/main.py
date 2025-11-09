from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from typing import Optional, List
import uvicorn
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import redis

load_dotenv()

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
DATABASE_URL = os.getenv("DATABASE_URL")

# Database Setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Redis Setup
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    db=int(os.getenv("REDIS_DB", 0)),
    decode_responses=True
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

app = FastAPI(title="User Authentication Service", version="1.0.0")

# Database Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    name = Column(String, nullable=False)
    phone = Column(String)
    role = Column(String, default="user")
    is_active = Column(Boolean, default=True)
    kyc_status = Column(String, default="pending")  # New field that will cascade changes
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# Pydantic Models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    phone: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    email: str
    name: str
    phone: Optional[str]
    role: str
    is_active: bool
    kyc_status: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class UserUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    kyc_status: Optional[str] = None

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Check if token is blacklisted
        if redis_client.get(f"blacklist:{token}"):
            raise credentials_exception
            
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise credentials_exception
    return user

# API Endpoints
@app.post("/api/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    # Check if user already exists
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    new_user = User(
        email=user.email,
        password_hash=hashed_password,
        name=user.name,
        phone=user.phone
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Publish event to Kafka (for other services)
    # kafka_producer.send('user.created', {'user_id': new_user.id, 'email': new_user.email})
    
    return new_user

@app.post("/api/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    access_token = create_access_token(data={"sub": str(user.id)})
    
    # Store session in Redis
    redis_client.setex(
        f"session:{user.id}:{access_token}",
        ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "active"
    )
    
    return {"access_token": access_token, "token_type": "bearer", "user": user}

@app.get("/api/auth/verify-token")
async def verify_token(current_user: User = Depends(get_current_user)):
    return {"valid": True, "user_id": current_user.id, "email": current_user.email}

@app.get("/api/auth/user/{user_id}", response_model=UserResponse)
async def get_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.put("/api/auth/user/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int, 
    user_update: UserUpdate, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.id != user_id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Track if KYC status changed (this will cascade to other services)
    kyc_changed = False
    old_kyc_status = user.kyc_status
    
    if user_update.name:
        user.name = user_update.name
    if user_update.phone:
        user.phone = user_update.phone
    if user_update.kyc_status:
        user.kyc_status = user_update.kyc_status
        kyc_changed = True
    
    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    
    # Publish event if KYC status changed (cascades to Wallet, Payment, Notification services)
    if kyc_changed:
        # kafka_producer.send('user.kyc_updated', {
        #     'user_id': user.id,
        #     'old_status': old_kyc_status,
        #     'new_status': user.kyc_status
        # })
        print(f"KYC Status changed for user {user.id}: {old_kyc_status} -> {user.kyc_status}")
        print("This change will cascade to: Wallet Service, Payment Service, Notification Service")
    
    return user

@app.post("/api/auth/logout")
async def logout(token: str = Depends(oauth2_scheme), current_user: User = Depends(get_current_user)):
    # Blacklist the token
    redis_client.setex(f"blacklist:{token}", ACCESS_TOKEN_EXPIRE_MINUTES * 60, "true")
    # Remove session
    redis_client.delete(f"session:{current_user.id}:{token}")
    return {"message": "Successfully logged out"}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "auth-service",
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVICE_PORT", 8001)))