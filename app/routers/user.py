from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from app.database import get_db
from app import models, schemas
from app.dependencies import get_current_user
from app.security import (
    verify_password, hash_password,
    revoke_all_user_tokens
)

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/me", response_model=schemas.UserResponse)
def get_profile(current_user: models.User = Depends(get_current_user)):
    """Get the current user's profile."""
    return current_user


@router.post("/me/change-password")
def change_password(
    data: schemas.ChangePasswordRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Change the current user's password.
    Automatically revokes all refresh tokens — logs out all devices.
    """
    if not verify_password(data.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if data.current_password == data.new_password:
        raise HTTPException(
            status_code=400,
            detail="New password must be different from current password"
        )

    current_user.hashed_password = hash_password(data.new_password)
    current_user.updated_at      = datetime.utcnow()
    db.commit()

    # Revoke all refresh tokens — security best practice after password change
    revoke_all_user_tokens(db, current_user.id)

    return {
        "message": "Password changed successfully. All other sessions have been logged out."
    }


@router.get("/me/sessions")
def get_active_sessions(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List all active refresh token sessions for the current user.
    Shows what devices are logged in.
    """
    from datetime import datetime as dt
    active_tokens = db.query(models.RefreshToken).filter(
        models.RefreshToken.user_id   == current_user.id,
        models.RefreshToken.revoked   == False,
        models.RefreshToken.expires_at > dt.utcnow()
    ).all()

    return {
        "active_sessions": [
            {
                "id":          t.id,
                "created_at":  t.created_at,
                "expires_at":  t.expires_at,
                "user_agent":  t.user_agent,
                "ip_address":  t.ip_address,
            }
            for t in active_tokens
        ],
        "count": len(active_tokens)
    }