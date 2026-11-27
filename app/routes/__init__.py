"""HTTP routes (thin layer). Real logic + all checks live in services/ and security/."""
from functools import wraps

from flask import g

from ..security.access_control import AccessDenied


def login_required(view):
    """Decorator: the user must have a valid server-side session.
    (Authentication only — authorization is checked separately per action.)"""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.get("user") is None:
            raise AccessDenied("Login required", 401)
        return view(*args, **kwargs)
    return wrapper
