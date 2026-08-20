from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from datetime import datetime

from app.database import get_db
from app import models, schemas
from app.security import (
    hash_password, verify_password, 
    create_access_token, generate_refresh_token,
    store_refresh_token, get_refresh_token,
    revoke_refresh_token, revoke_all_user_tokens,
    blacklist_token, decode_access_token, 
    is_token_blacklisted, cleanup_expired_blacklist,
    ACCESS_TOKEN_EXPIRE
)
from app.dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=schemas.UserResponse,
                status_code=status.HTTP_201_CREATED)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user.
    """
    # Check if email or username already exists
    existing_user = db.query(models.User).filter(
        (models.User.email == user.email) | 
        (models.User.username == user.username)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email or username already registered"
        )

    # Hash the password
    hashed_password = hash_password(user.password)

    # Create the user
    new_user = models.User(
        email=user.email,
        username=user.username,
        hashed_password=hashed_password,
        role=models.UserRole.user  # Default role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/login", response_model=schemas.TokenResponse)
def login(
    data: schemas.LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Login with email and password.
    Returns an access token (15 min) and a refresh token (7 days).
    Store both securely — the refresh token is never stored in plain text server-side.
    """
    user = db.query(models.User).filter(models.User.email == data.email).first()
 
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
 
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled"
        )
 
    # Create tokens
    access_token, jti    = create_access_token(user.id, user.username, user.role.value)
    raw_refresh, rf_hash = generate_refresh_token()
 
    # Store refresh token hash
    user_agent = request.headers.get("user-agent", "")
    ip_address = request.client.host if request.client else None
 
    store_refresh_token(db, user.id, rf_hash, user_agent, ip_address)
 
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
 
    return schemas.TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=ACCESS_TOKEN_EXPIRE * 60
    )


@router.post("/refresh", response_model=schemas.AccessTokenResponse)
def refresh_token(data: schemas.RefreshRequest, db: Session = Depends(get_db)):
    """
    Exchange a valid refresh token for a new access token.
    The refresh token is NOT rotated — same refresh token persists until logout or expiry.
    """
    rt = get_refresh_token(db, data.refresh_token)
 
    if not rt:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
 
    user = db.query(models.User).filter(models.User.id == rt.user_id).first()
 
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or disabled"
        )
 
    access_token, _ = create_access_token(user.id, user.username, user.role.value)
 
    return schemas.AccessTokenResponse(
        access_token=access_token,
        expires_in=ACCESS_TOKEN_EXPIRE * 60
    )
 
 
@router.post("/logout")
def logout(
    data: schemas.RefreshRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    """
    Logout the current user.
    Revokes the refresh token and blacklists the current access token.
    """
    # Revoke refresh token
    revoke_refresh_token(db, data.refresh_token)
 
    # Blacklist the current access token
    auth_header = ""
    if request:
        auth_header = request.headers.get("authorization", "")
 
    if auth_header.startswith("Bearer "):
        token   = auth_header.split(" ")[1]
        payload = decode_access_token(token)
        if payload:
            from datetime import datetime as dt
            expires_at = dt.utcfromtimestamp(payload["exp"])
            blacklist_token(db, payload["jti"], expires_at)
 
    # Cleanup expired blacklist entries periodically
    cleanup_expired_blacklist(db)
 
    return {"message": "Successfully logged out"}
 
 
@router.post("/logout-all")
def logout_all_devices(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Revoke all refresh tokens for this user — logs out all devices.
    Useful for security events like password change or account compromise.
    """
    revoke_all_user_tokens(db, current_user.id)
    return {"message": "Logged out from all devices"}
 
 
@router.post("/verify-token", response_model=schemas.VerifyTokenResponse)
def verify_token(data: schemas.VerifyTokenRequest, db: Session = Depends(get_db)):
    """
    Verify an access token. Intended for other microservices to call.
    Returns user info if valid, error details if not.
    This is the token introspection endpoint.
    """
    payload = decode_access_token(data.token)
 
    if not payload:
        return schemas.VerifyTokenResponse(
            valid=False, message="Invalid or expired token"
        )
 
    jti = payload.get("jti")
    if jti and is_token_blacklisted(db, jti):
        return schemas.VerifyTokenResponse(
            valid=False, message="Token has been revoked"
        )
 
    user = db.query(models.User).filter(
        models.User.id == int(payload["sub"])
    ).first()
 
    if not user or not user.is_active:
        return schemas.VerifyTokenResponse(
            valid=False, message="User not found or disabled"
        )
 
    return schemas.VerifyTokenResponse(
        valid=True,
        user_id=user.id,
        username=user.username,
        role=user.role.value,
        message="Token is valid"
    )
