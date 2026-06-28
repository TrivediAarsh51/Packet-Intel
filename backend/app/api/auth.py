import os
import secrets
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User, AuditLog
from ..core.auth import verify_password, get_password_hash, create_access_token, decode_token, get_current_admin_user, oauth2_scheme
from ..schemas.user import UserCreate, Token, UserResponse
from pydantic import BaseModel

router = APIRouter()

ALLOW_PUBLIC_SIGNUP = os.getenv("ALLOW_PUBLIC_SIGNUP", "false").lower() == "true"

class AdminUserCreate(BaseModel):
    username: str
    email: str
    role: str

@router.post("/signup", response_model=Token)
async def signup(user_in: UserCreate, db: Session = Depends(get_db)):
    if not ALLOW_PUBLIC_SIGNUP:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Public signup is disabled")
    
    # Check existing
    if db.query(User).filter(User.username == user_in.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == user_in.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        role='analyst',
        requires_password_reset=False
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    token = create_access_token(data={"sub": user.username, "role": user.role, "requires_password_reset": user.requires_password_reset})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user
    }

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
        
    if user.requires_password_reset:
        return {"force_reset": True}

    token = create_access_token(data={"sub": user.username, "role": user.role, "requires_password_reset": user.requires_password_reset})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user
    }

@router.post("/create-user")
async def create_user(
    user_in: AdminUserCreate, 
    db: Session = Depends(get_db), 
    admin: User = Depends(get_current_admin_user)
):
    valid_roles = ["analyst", "operator", "auditor", "super_admin"]
    if user_in.role not in valid_roles:
        raise HTTPException(status_code=400, detail="Invalid role")
    if db.query(User).filter(User.username == user_in.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == user_in.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    temp_password = secrets.token_urlsafe(16)
    new_user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=get_password_hash(temp_password),
        role=user_in.role,
        requires_password_reset=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    audit_log = AuditLog(
        actor_id=admin.id,
        action="create_user",
        target=new_user.username
    )
    db.add(audit_log)
    db.commit()
    
    return {
        "username": new_user.username,
        "temporary_password": temp_password
    }

@router.get("/me", response_model=UserResponse)
async def get_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
