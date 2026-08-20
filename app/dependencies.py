"""
Auth Service Dependencies
Reusable FastAPI dependencies for route protection.
Import these into any router that needs authentication.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.database import get_db
from app import models
from app.security import decode_access_token, is_token_blacklisted

bearer_scheme = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db)
) -> models.User:
    """
    Extracts and validates the JWT from the Authorization header.
    Returns the current user or raises 401.
    Use this as a dependency on any protected route.
    """
    token = credentials.credentials
 
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check blacklist — catches logged-out tokens
    jti = payload.get("jti")
    if jti and is_token_blacklisted(db, jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
 
    user_id = int(payload.get("sub"))
    user    = db.query(models.User).filter(models.User.id == user_id).first()
 
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )
 
    return user
 
 
def get_current_active_user(
    current_user: models.User = Depends(get_current_user)
) -> models.User:
    """Alias for clarity in route signatures."""
    return current_user
 
 
def require_role(*roles: str):
    """
    Factory that returns a dependency requiring specific roles.
    Usage:
        @router.get("/admin", dependencies=[Depends(require_role("admin"))])
    Or:
        @router.get("/mod", dependencies=[Depends(require_role("admin", "moderator"))])
    """
    def role_checker(
        current_user: models.User = Depends(get_current_user)
    ) -> models.User:
        if current_user.role.value not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {' or '.join(roles)}"
            )
        return current_user
    return role_checker
 
 
def require_admin(
    current_user: models.User = Depends(require_role("admin"))
) -> models.User:
    return current_user
 
 
def require_moderator(
    current_user: models.User = Depends(require_role("admin", "moderator"))
) -> models.User:
    return current_user
