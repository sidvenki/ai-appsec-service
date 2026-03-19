"""
Authentication and RBAC middleware for AI AppSec Service.

Provides:
  - get_current_user(): FastAPI dependency that extracts user from session cookie
  - require_role(*roles): dependency factory that enforces role-based access
  - login_required: shortcut dependency that requires any authenticated user
"""

import datetime
from typing import Optional
from fastapi import Request, HTTPException, Depends
from sqlalchemy.orm import Session as DBSession

from src.models.database import get_db, User, Session


def get_session_token(request: Request) -> Optional[str]:
    """Extract session token from cookie."""
    return request.cookies.get("session_token")


def get_current_user(
    request: Request,
    db: DBSession = Depends(get_db),
) -> Optional[User]:
    """
    FastAPI dependency: returns the current authenticated User or None.
    Reads the session_token cookie, validates it, returns the user.
    """
    token = get_session_token(request)
    if not token:
        return None

    session = (
        db.query(Session)
        .filter(
            Session.token == token,
            Session.is_active == True,
            Session.expires_at > datetime.datetime.utcnow(),
        )
        .first()
    )
    if not session:
        return None

    user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
    return user


def require_login(
    request: Request,
    db: DBSession = Depends(get_db),
) -> User:
    """Dependency: requires any authenticated user. Raises 401 if not logged in."""
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


class RequireRole:
    """
    Dependency factory for role-based access control.

    Usage in route:
        @router.get("/admin/users", dependencies=[Depends(RequireRole("admin"))])
        def list_users(...):
            ...

    Or to get the user object:
        @router.get("/scanner/queue")
        def scanner_queue(user: User = Depends(RequireRole("scanner", "admin"))):
            ...
    """

    def __init__(self, *allowed_roles: str):
        self.allowed_roles = allowed_roles

    def __call__(
        self,
        request: Request,
        db: DBSession = Depends(get_db),
    ) -> User:
        user = get_current_user(request, db)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if user.role not in self.allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user


def create_session(db: DBSession, user: User, hours: int = 24) -> Session:
    """Create a new session for the user."""
    session = Session(
        user_id=user.id,
        token=Session.generate_token(),
        expires_at=datetime.datetime.utcnow() + datetime.timedelta(hours=hours),
    )
    db.add(session)

    # Update last login
    user.last_login = datetime.datetime.utcnow()
    db.commit()
    db.refresh(session)
    return session


def invalidate_session(db: DBSession, token: str):
    """Invalidate a session by token."""
    session = db.query(Session).filter(Session.token == token).first()
    if session:
        session.is_active = False
        db.commit()
