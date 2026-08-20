from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime

from app.database import get_db
from app import models, schemas
from app.dependencies import require_admin
from app.security import revoke_all_user_tokens

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/users", response_model=List[schemas.AdminUserResponse])
def list_all_users(
    skip:   int = 0,
    limit:  int = 50,
    role:   str = None,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin)
):
    """List all users. Admin only."""
    q = db.query(models.User)
    if role:
        q = q.filter(models.User.role == role)
    users = q.offset(skip).limit(limit).all()

    result = []
    for user in users:
        active_count = db.query(models.RefreshToken).filter(
            models.RefreshToken.user_id   == user.id,
            models.RefreshToken.revoked   == False,
            models.RefreshToken.expires_at > datetime.utcnow()
        ).count()

        result.append(schemas.AdminUserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            role=user.role,
            is_active=user.is_active,
            is_verified=user.is_verified,
            created_at=user.created_at,
            last_login=user.last_login,
            active_token_count=active_count,
        ))
    return result


@router.get("/users/{user_id}", response_model=schemas.AdminUserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    active_count = db.query(models.RefreshToken).filter(
        models.RefreshToken.user_id   == user.id,
        models.RefreshToken.revoked   == False,
        models.RefreshToken.expires_at > datetime.utcnow()
    ).count()

    return schemas.AdminUserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
        is_verified=user.is_verified,
        created_at=user.created_at,
        last_login=user.last_login,
        active_token_count=active_count,
    )


@router.patch("/users/{user_id}", response_model=schemas.UserResponse)
def update_user(
    user_id: int,
    data: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_admin: models.User = Depends(require_admin)
):
    """Update a user's role, active status, or verification status."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_admin.id:
        raise HTTPException(
            status_code=400,
            detail="Cannot modify your own admin account"
        )

    if data.role       is not None: user.role        = data.role
    if data.is_active  is not None: user.is_active   = data.is_active
    if data.is_verified is not None: user.is_verified = data.is_verified

    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)

    # If disabling account, revoke all their tokens
    if data.is_active is False:
        revoke_all_user_tokens(db, user_id)

    return user


@router.post("/users/{user_id}/force-logout")
def force_logout_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin)
):
    """Revoke all active sessions for a user. Admin only."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    revoke_all_user_tokens(db, user_id)
    return {"message": f"All sessions revoked for {user.username}"}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: models.User = Depends(require_admin)
):
    """Permanently delete a user account. Admin only."""
    if user_id == current_admin.id:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete your own account"
        )

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    return {"message": f"User '{user.username}' permanently deleted"}


@router.get("/stats")
def system_stats(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin)
):
    """System-wide auth statistics."""
    from datetime import timedelta
    now   = datetime.utcnow()
    day   = now - timedelta(days=1)
    week  = now - timedelta(days=7)

    total_users    = db.query(models.User).count()
    active_users   = db.query(models.User).filter(models.User.is_active == True).count()
    verified_users = db.query(models.User).filter(models.User.is_verified == True).count()
    new_today      = db.query(models.User).filter(models.User.created_at >= day).count()
    new_this_week  = db.query(models.User).filter(models.User.created_at >= week).count()
    active_sessions = db.query(models.RefreshToken).filter(
        models.RefreshToken.revoked   == False,
        models.RefreshToken.expires_at > now
    ).count()
    blacklisted    = db.query(models.TokenBlacklist).filter(
        models.TokenBlacklist.expires_at > now
    ).count()

    return {
        "total_users":      total_users,
        "active_users":     active_users,
        "verified_users":   verified_users,
        "new_today":        new_today,
        "new_this_week":    new_this_week,
        "active_sessions":  active_sessions,
        "blacklisted_tokens": blacklisted,
        "roles": {
            role.value: db.query(models.User).filter(
                models.User.role == role
            ).count()
            for role in models.UserRole
        }
    }