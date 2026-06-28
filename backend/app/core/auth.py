from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
import bcrypt
from fastapi.security import OAuth2PasswordBearer
import os
from dotenv import load_dotenv
load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY', 'changeme-secret-key')
ALGORITHM = os.getenv('ALGORITHM', 'HS256')
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', '60'))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/api/auth/login', auto_error=False)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({'exp': expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User

ROLE_PERMISSIONS = {
    "analyst": ["view_packets"],
    "operator": ["view_packets", "manage_capture", "manage_cases"],
    "auditor": ["view_packets", "export_logs"],
    "super_admin": ["view_packets", "manage_capture", "delete_session", "export_logs", "manage_users", "generate_credentials", "manage_cases"]
}

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

def require_permission(permission_name: str):
    def permission_dependency(current_user: User = Depends(get_current_user)):
        perms = ROLE_PERMISSIONS.get(current_user.role, [])
        if permission_name not in perms:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user
    return permission_dependency

def get_current_admin_user(current_user: User = Depends(get_current_user)):
    if current_user.role != "super_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Requires super_admin role")
    return current_user

