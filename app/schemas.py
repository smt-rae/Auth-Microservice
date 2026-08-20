from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from datetime import datetime
from app.models import UserRole
import re


# ── Auth

class RegisterRequest(BaseModel):
    email:  EmailStr
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def valid_username(cls, v):
        if len(v) < 3 or len(v) > 32:
            raise ValueError("Username must be between 3 and 32 characters")
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username can only contain letters, numbers, _ and -")
        return v.lower()

    @field_validator("password")
    @classmethod
    def valid_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be a least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one number")
        return v


class LoginRequest(BaseModel):
    email:  EmailStr
    password: str


class LoginRequest(BaseModel):
    email:  EmailStr
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str
 
    @field_validator("new_password")
    @classmethod
    def strong_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one number")
        return v
 
 
class VerifyTokenRequest(BaseModel):
    token: str


# ── Responses

class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int           # Seconds until access token expires


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int
 
 
class UserResponse(BaseModel):
    id:          int
    email:       str
    username:    str
    role:        UserRole
    is_active:   bool
    is_verified: bool
    created_at:  datetime
    last_login:  Optional[datetime]
 
    class Config:
        from_attributes = True
 
 
class TokenPayload(BaseModel):
    sub:  str          # User ID as string
    role: str
    jti:  str          # Unique token ID for blacklisting
    exp:  int
    type: str          # "access" or "refresh"
 
 
class VerifyTokenResponse(BaseModel):
    valid:    bool
    user_id:  Optional[int]
    username: Optional[str]
    role:     Optional[str]
    message:  str


# ── Admin

class UserUpdate(BaseModel):
    role:       Optional[UserRole] = None
    is_active:  Optional[bool]     = None
    is_verified: Optional[bool]    = None
 
 
class AdminUserResponse(BaseModel):
    id:                  int
    email:               str
    username:            str
    role:                UserRole
    is_active:           bool
    is_verified:         bool
    created_at:          datetime
    last_login:          Optional[datetime]
    active_token_count:  int
 
    class Config:
        from_attributes = True
        