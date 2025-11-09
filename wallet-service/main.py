# Wallet Service (Module B) - Port 8002
# Dependencies: Auth Service (A)
# Dependents: Payment Service (C), Reporting Service (F)

from fastapi import FastAPI, HTTPException, Depends, Header, status
from datetime import datetime
from typing import Optional, List
from decimal import Decimal
import uvicorn
from pydantic import BaseModel, validator
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Numeric, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import enum
import httpx
import redis

load_dotenv()

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://localhost:8001")

# NEW: Configurable precision (changed from 2 to 4)
BALANCE_PRECISION = 4
BALANCE_DECIMAL_PLACES = Decimal(10) ** -BALANCE_PRECISION

# Database Setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Redis Setup
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    decode_responses=True
)

app = FastAPI(title="Wallet Service", version="2.0.0")

# Enums
class WalletStatus(str, enum.Enum):
    ACTIVE = "active"
    FROZEN = "frozen"
    CLOSED = "closed"

class TransactionType(str, enum.Enum):
    CREDIT = "credit"
    DEBIT = "debit"

# Database Models
class Wallet(Base):
    __tablename__ = "wallets"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    currency = Column(String, default="USD")
    # CHANGED: DECIMAL(10,2) -> DECIMAL(20,4) for higher precision
    balance = Column(Numeric(20, 4), default=0.0000)
    status = Column(SQLEnum(WalletStatus), default=WalletStatus.ACTIVE)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class WalletTransaction(Base):
    __tablename__ = "wallet_transactions"
    
    id = Column(Integer, primary_key=True, index=True)
    wallet_id = Column(Integer, nullable=False, index=True)
    type = Column(SQLEnum(TransactionType), nullable=False)
    # CHANGED: Also updated transaction amounts to support new precision
    amount = Column(Numeric(20, 4), nullable=False)
    balance_after = Column(Numeric(20, 4), nullable=False)
    reference_id = Column(String, index=True)
    description = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# Pydantic Models
class WalletCreate(BaseModel):
    currency: str = "USD"

class WalletResponse(BaseModel):
    id: int
    user_id: int
    currency: str
    balance: float
    status: str
    created_at: datetime
    
    @validator('balance', pre=True)
    def round_balance(cls, v):
        """Ensure balance respects new precision"""
        if isinstance(v, Decimal):
            return float(v.quantize(BALANCE_DECIMAL_PLACES))
        return round(float(v), BALANCE_PRECISION)
    
    class Config:
        from_attributes = True

class TransactionResponse(BaseModel):
    id: int
    wallet_id: int
    type: str
    amount: float
    balance_after: float
    reference_id: Optional[str]
    description: Optional[str]
    timestamp: datetime
    
    @validator('amount', 'balance_after', pre=True)
    def round_amounts(cls, v):
        """Ensure amounts respect new precision"""
        if isinstance(v, Decimal):
            return float(v.quantize(BALANCE_DECIMAL_PLACES))
        return round(float(v), BALANCE_PRECISION)
    
    class Config:
        from_attributes = True

class BalanceResponse(BaseModel):
    wallet_id: int
    balance: float
    currency: str
    precision: int  # NEW: Advertise precision to consumers
    
    @validator('balance', pre=True)
    def round_balance(cls, v):
        if isinstance(v, Decimal):
            return float(v.quantize(BALANCE_DECIMAL_PLACES))
        return round(float(v), BALANCE_PRECISION)

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency: Verify user with Auth Service
async def verify_user_token(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{AUTH_SERVICE_URL}/api/auth/verify-token",
                headers={"Authorization": authorization}
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=401, detail="Invalid token")
            
            user_data = response.json()
            return user_data
    except httpx.RequestError:
        raise HTTPException(status_code=503, detail="Auth service unavailable")

async def get_user_details(user_id: int, authorization: str):
    """
    DEPENDENCY ON AUTH SERVICE (Module A)
    Fetches user details including KYC status
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{AUTH_SERVICE_URL}/api/auth/user/{user_id}",
                headers={"Authorization": authorization}
            )
            
            if response.status_code != 200:
                return None
            
            return response.json()
    except httpx.RequestError:
        return None

# API Endpoints
@app.post("/api/wallet/create", response_model=WalletResponse, status_code=status.HTTP_201_CREATED)
async def create_wallet(
    wallet_data: WalletCreate,
    user_data: dict = Depends(verify_user_token),
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    user_id = user_data["user_id"]
    
    # CRITICAL: Check if user already has a wallet
    existing_wallet = db.query(Wallet).filter(
        Wallet.user_id == user_id,
        Wallet.currency == wallet_data.currency
    ).first()
    
    if existing_wallet:
        raise HTTPException(status_code=400, detail="Wallet already exists for this currency")
    
    # DEPENDENCY IMPACT: Fetch user details to check KYC status
    # If Auth Service (Module A) changes KYC field, this breaks
    user_details = await get_user_details(user_id, authorization)
    
    if not user_details:
        raise HTTPException(status_code=404, detail="User not found")
    
    # NEW VALIDATION: Check KYC status (cascaded from Auth Service)
    if user_details.get("kyc_status") != "verified":
        raise HTTPException(
            status_code=403, 
            detail=f"KYC verification required. Current status: {user_details.get('kyc_status')}"
        )
    
    # Create wallet
    new_wallet = Wallet(
        user_id=user_id,
        currency=wallet_data.currency,
        balance=Decimal('0.0000')  # NEW: Initialize with 4 decimal places
    )
    
    db.add(new_wallet)
    db.commit()
    db.refresh(new_wallet)
    
    # Publish event
    # kafka_producer.send('wallet.created', {'wallet_id': new_wallet.id, 'user_id': user_id})
    
    return new_wallet

@app.get("/api/wallet/{wallet_id}", response_model=WalletResponse)
async def get_wallet(
    wallet_id: int,
    user_data: dict = Depends(verify_user_token),
    db: Session = Depends(get_db)
):
    wallet = db.query(Wallet).filter(Wallet.id == wallet_id).first()
    
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    # Verify ownership
    if wallet.user_id != user_data["user_id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    return wallet

@app.get("/api/wallet/user/{user_id}", response_model=List[WalletResponse])
async def get_user_wallets(
    user_id: int,
    user_data: dict = Depends(verify_user_token),
    db: Session = Depends(get_db)
):
    # Verify requesting user
    if user_id != user_data["user_id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    wallets = db.query(Wallet).filter(Wallet.user_id == user_id).all()
    return wallets

@app.get("/api/wallet/{wallet_id}/balance", response_model=BalanceResponse)
async def get_balance(
    wallet_id: int,
    user_data: dict = Depends(verify_user_token),
    db: Session = Depends(get_db)
):
    wallet = db.query(Wallet).filter(Wallet.id == wallet_id).first()
    
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    if wallet.user_id != user_data["user_id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Check Redis cache first
    cache_key = f"balance:{wallet_id}"
    cached_balance = redis_client.get(cache_key)
    
    if cached_balance:
        return {
            "wallet_id": wallet_id,
            "balance": float(cached_balance),
            "currency": wallet.currency,
            "precision": BALANCE_PRECISION  # NEW: Include precision info
        }
    
    # Cache balance
    redis_client.setex(cache_key, 60, str(wallet.balance))
    
    return {
        "wallet_id": wallet_id,
        "balance": float(wallet.balance),
        "currency": wallet.currency,
        "precision": BALANCE_PRECISION  # NEW: Include precision info
    }

@app.get("/api/wallet/{wallet_id}/transactions", response_model=List[TransactionResponse])
async def get_transactions(
    wallet_id: int,
    limit: int = 50,
    user_data: dict = Depends(verify_user_token),
    db: Session = Depends(get_db)
):
    # Verify wallet ownership
    wallet = db.query(Wallet).filter(Wallet.id == wallet_id).first()
    if not wallet or wallet.user_id != user_data["user_id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    transactions = db.query(WalletTransaction).filter(
        WalletTransaction.wallet_id == wallet_id
    ).order_by(WalletTransaction.timestamp.desc()).limit(limit).all()
    
    return transactions

@app.put("/api/wallet/{wallet_id}/status")
async def update_wallet_status(
    wallet_id: int,
    new_status: WalletStatus,
    user_data: dict = Depends(verify_user_token),
    db: Session = Depends(get_db)
):
    wallet = db.query(Wallet).filter(Wallet.id == wallet_id).first()
    
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    if wallet.user_id != user_data["user_id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    old_status = wallet.status
    wallet.status = new_status
    wallet.updated_at = datetime.utcnow()
    
    db.commit()
    
    # Publish event (affects Payment Service)
    # kafka_producer.send('wallet.status_changed', {
    #     'wallet_id': wallet_id,
    #     'old_status': old_status,
    #     'new_status': new_status
    # })
    
    # Invalidate cache
    redis_client.delete(f"balance:{wallet_id}")
    
    return {"message": "Wallet status updated", "new_status": new_status}

@app.get("/api/wallet/config/precision")
async def get_precision_config():
    """NEW: Expose precision configuration for consumers"""
    return {
        "balance_precision": BALANCE_PRECISION,
        "balance_decimal_places": BALANCE_PRECISION,
        "max_balance": "99999999999999999.9999",
        "version": "2.0.0",
        "breaking_change": True,
        "migration_info": "Balance precision changed from 2 to 4 decimal places"
    }

@app.get("/health")
async def health_check():
    # Check Auth Service dependency
    auth_healthy = False
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{AUTH_SERVICE_URL}/health", timeout=2.0)
            auth_healthy = response.status_code == 200
    except:
        pass
    
    return {
        "status": "healthy" if auth_healthy else "degraded",
        "service": "wallet-service",
        "version": "2.0.0",
        "balance_precision": BALANCE_PRECISION,
        "breaking_changes": ["Balance precision: 2 -> 4 decimal places"],
        "dependencies": {
            "auth-service": "healthy" if auth_healthy else "unhealthy"
        },
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVICE_PORT", 8002)))