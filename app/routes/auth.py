"""
app/routes/auth.py
==================
Registration, login, logout, password change and account recovery pages.
"""
from flask import (Blueprint, flash, g, make_response, redirect, render_template,
                   request, url_for)

from ..db import get_db
from ..security import audit, sessions
from ..services import users
from . import login_required

bp = Blueprint("auth", __name__)


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            _uid, recovery_code = users.register(get_db(), request.form.get("username", ""),
                                                 request.form.get("password", ""))
        except users.UserError as exc:
            flash(str(exc), "error")
            return render_template("auth/register.html"), 400
        # Recovery code is shown ONCE and never stored in plaintext
        return render_template("auth/recovery_code.html", recovery_code=recovery_code,
                               next_url=url_for("auth.login"))
    return render_template("auth/register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        conn = get_db()
        try:
            user, keys = users.authenticate(conn, request.form.get("username", ""),
                                            request.form.get("password", ""))
        except users.UserError as exc:
            flash(str(exc), "error")
            return render_template("auth/login.html"), 401
        token = sessions.create_session(conn, user["id"], keys)
        resp = make_response(redirect(url_for("documents.dashboard")))
        sessions.set_cookie(resp, token)
        return resp
    return render_template("auth/login.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    sessions.destroy_session(get_db(), g.session["token_hash"])  # also wipes keys from RAM
    audit.record("auth.logout", target_type="user", target_id=g.user["id"])
    resp = make_response(redirect(url_for("auth.login")))
    sessions.clear_cookie(resp)
    flash("Logged out.", "info")
    return resp


@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        try:
            code = users.change_password(get_db(), g.user, g.session["token_hash"], g.keys,
                                         request.form.get("old_password", ""),
                                         request.form.get("new_password", ""))
        except users.UserError as exc:
            flash(str(exc), "error")
            return render_template("auth/account.html"), 400
        flash("Password changed. All your other sessions were logged out.", "info")
        return render_template("auth/recovery_code.html", recovery_code=code,
                               next_url=url_for("documents.dashboard"))
    return render_template("auth/account.html")


@bp.route("/recover", methods=["GET", "POST"])
def recover():
    if request.method == "POST":
        try:
            code = users.recover_account(get_db(), request.form.get("username", ""),
                                         request.form.get("recovery_code", ""),
                                         request.form.get("new_password", ""))
        except users.UserError as exc:
            flash(str(exc), "error")
            return render_template("auth/recover.html"), 400
        flash("Password reset. Log in with your new password.", "info")
        return render_template("auth/recovery_code.html", recovery_code=code,
                               next_url=url_for("auth.login"))
    return render_template("auth/recover.html")
