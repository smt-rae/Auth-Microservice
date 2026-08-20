from sqlalchemy import (
    Column, Integer, String, Boolean,
    DateTime, ForeignKey, Enum as SAEnum
)
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime
import enum


class UserRole(str, enum.Enum):
    user      = "user"
    moderator = "moderator"
    admin     = "admin"


class User(Base):
    __tablename__ = "users"

    id              = Column(Integer, primary_key=True, index=True)
    email           = Column(String, unique=True, nullable=False, index=True)
    username        = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    role            = Column(SAEnum(UserRole), default=UserRole.user)
    is_active       = Column(Boolean, default=True)
    is_verified     = Column(Boolean, default=False)
    created_at      = Column(DateTime, default=datetime.utcnow)
    updated_at      = Column(DateTime, default=datetime.utcnow,
                             onupdate=datetime.utcnow)
    last_login      = Column(DateTime, nullable=True)

    refresh_tokens  = relationship("RefreshToken", back_populates="user",
                                   cascade="all, delete")


class RefreshToken(Base):
    """
    Refresh tokens are stored as hashes — never the raw token.
    This means a database breach doesn't expose valid tokens.
    """
    __tablename__ = "refresh_tokens"

    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash  = Column(String, nullable=False, unique=True, index=True)
    expires_at  = Column(DateTime, nullable=False)
    revoked     = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=datetime.utcnow)
    revoked_at  = Column(DateTime, nullable=True)
    user_agent  = Column(String, nullable=True)   # Track what device issued it
    ip_address  = Column(String, nullable=True)

    user        = relationship("User", back_populates="refresh_tokens")


class TokenBlacklist(Base):
    """
    Blacklisted access tokens — logged out before expiry.
    Cleaned up when tokens expire naturally.
    """
    __tablename__ = "token_blacklist"

    id         = Column(Integer, primary_key=True, index=True)
    jti        = Column(String, unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)