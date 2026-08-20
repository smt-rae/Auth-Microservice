"""
Auth Service Security Layer
Handles all cryptographic operations:
  - Password hashing with bcrypt
  - JWT access token creation and verification
  - Refresh token generation and hashing
  - Token blacklist management
"""

import os
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app import models
from app.schemas import TokenPayload 

# ── Config

SECRET_KEY            = os.getenv("SECRET_KEY", secrets.token_hex(32))
ALGORITHM             = "HS256"
ACCESS_TOKEN_EXPIRE   = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))
REFRESH_TOKEN_EXPIRE  = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))
 
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── Password

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


# ── Access Tokens

def create_access_token(user_id: int, username: str, role: str) -> tuple:
    """
    Creates a short-lived JWT access token.
    Returns (token, jti) — the JTI is stored for blacklisting on logout.
    """
    jti     = str(uuid.uuid4())
    expires = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE)
 
    payload = {
        "sub":      str(user_id),
        "username": username,
        "role":     role,
        "jti":      jti,
        "type":     "access",
        "exp":      expires,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, jti
 
 
def decode_access_token(token: str) -> Optional[dict]:
    """
    Decodes and validates a JWT access token.
    Returns payload dict or None if invalid/expired.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload
    except JWTError:
        return None
 
 
# ── Refresh Tokens

def generate_refresh_token() -> tuple:
    """
    Generates a cryptographically secure refresh token.
    Returns (raw_token, hashed_token).
    Raw token is returned to the client once — never stored.
    Only the hash is stored in the database.
    """
    raw_token = secrets.token_urlsafe(64)
    hashed    = hashlib.sha256(raw_token.encode()).hexdigest()
    return raw_token, hashed
 
 
def hash_refresh_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()
 
 
def store_refresh_token(
    db: Session,
    user_id: int,
    token_hash: str,
    user_agent: str = None,
    ip_address: str = None
) -> models.RefreshToken:
    expires = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE)
    rt = models.RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires,
        user_agent=user_agent,
        ip_address=ip_address,
    )
    db.add(rt)
    db.commit()
    db.refresh(rt)
    return rt
 
 
def get_refresh_token(db: Session, raw_token: str) -> Optional[models.RefreshToken]:
    token_hash = hash_refresh_token(raw_token)
    return db.query(models.RefreshToken).filter(
        models.RefreshToken.token_hash == token_hash,
        models.RefreshToken.revoked    == False,
        models.RefreshToken.expires_at > datetime.utcnow()
    ).first()
 
 
def revoke_refresh_token(db: Session, raw_token: str) -> bool:
    rt = get_refresh_token(db, raw_token)
    if not rt:
        return False
    rt.revoked    = True
    rt.revoked_at = datetime.utcnow()
    db.commit()
    return True
 
 
def revoke_all_user_tokens(db: Session, user_id: int):
    """Revoke all refresh tokens for a user — useful for password change or security events."""
    db.query(models.RefreshToken).filter(
        models.RefreshToken.user_id == user_id,
        models.RefreshToken.revoked == False
    ).update({"revoked": True, "revoked_at": datetime.utcnow()})
    db.commit()
 
 
# ── Token Blacklist

def blacklist_token(db: Session, jti: str, expires_at: datetime):
    """Add an access token's JTI to the blacklist on logout."""
    entry = models.TokenBlacklist(jti=jti, expires_at=expires_at)
    db.add(entry)
    db.commit()
 
 
def is_token_blacklisted(db: Session, jti: str) -> bool:
    return db.query(models.TokenBlacklist).filter(
        models.TokenBlacklist.jti == jti,
        models.TokenBlacklist.expires_at > datetime.utcnow()
    ).first() is not None
 
 
def cleanup_expired_blacklist(db: Session):
    """Remove expired blacklist entries — call this periodically."""
    db.query(models.TokenBlacklist).filter(
        models.TokenBlacklist.expires_at <= datetime.utcnow()
    ).delete()
    db.commit()
    