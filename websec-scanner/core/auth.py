"""
Authentication: username/password login with server-side sessions.

Passwords are hashed with bcrypt (via passlib), never stored or logged in
plaintext. Sessions are random opaque tokens stored in SQLite and set as an
HttpOnly, Secure (in production), SameSite=Lax cookie -- not a JWT, so a
session can be revoked server-side instantly (e.g. deleting a user also
deletes their sessions).

On first startup, if no users exist yet, an admin account is created from
WEBSEC_ADMIN_USERNAME / WEBSEC_ADMIN_PASSWORD env vars (falling back to
admin / a random generated password printed to the server log once, so the
app is never left with a known default credential).
"""
from __future__ import annotations

import os
import secrets

from fastapi import Request, HTTPException
from passlib.context import CryptContext

from core import db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SESSION_COOKIE = "websec_session"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        return False


def bootstrap_admin() -> None:
    """Create the first admin user if the users table is empty."""
    if db.count_users() > 0:
        return

    username = os.environ.get("WEBSEC_ADMIN_USERNAME", "admin")
    password = os.environ.get("WEBSEC_ADMIN_PASSWORD")

    generated = False
    if not password:
        password = secrets.token_urlsafe(12)
        generated = True

    db.create_user(username, hash_password(password), is_admin=True)

    if generated:
        print("=" * 70)
        print(" WEBSEC SCANNER: no admin credentials were configured.")
        print(f" Created admin account automatically:")
        print(f"   username: {username}")
        print(f"   password: {password}")
        print(" Log in and consider changing this, or set WEBSEC_ADMIN_USERNAME")
        print(" and WEBSEC_ADMIN_PASSWORD as environment variables on your host")
        print(" so this doesn't regenerate on every fresh deploy.")
        print("=" * 70)


def create_session_for(username: str) -> str:
    token = secrets.token_urlsafe(32)
    db.create_session(token, username)
    return token


def get_current_user(request: Request) -> dict:
    """FastAPI dependency: raises 401 if not logged in, else returns the
    user dict ({"username", "is_admin"})."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Not logged in")
    user = db.get_session_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    return user


def get_current_admin(request: Request) -> dict:
    user = get_current_user(request)
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def is_cookie_secure() -> bool:
    """Only mark the session cookie Secure (HTTPS-only) when we're actually
    running behind HTTPS, so local http://127.0.0.1 testing still works.
    Render sets RENDER=true automatically on its platform, so production
    deploys there get secure cookies with zero extra config; anyone hosting
    elsewhere behind HTTPS can opt in with WEBSEC_FORCE_SECURE_COOKIES=1."""
    if os.environ.get("RENDER", "").lower() == "true":
        return True
    return os.environ.get("WEBSEC_FORCE_SECURE_COOKIES", "").lower() in ("1", "true", "yes")
