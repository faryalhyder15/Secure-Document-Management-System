"""
app/routes/admin.py
===================
Administrator pages (RBAC: system_role == 'admin').

What an administrator CAN do (Part 1.5 Q3):
  * list users, enable/disable accounts, change system roles
  * search and read the audit trail, verify its integrity
  * view a "suspicious activity" summary
  * scan storage for modified/missing blobs (hash comparison only)

What an administrator CANNOT do (Part 1.5 Q4 - least privilege):
  * read, download or decrypt anybody's documents. There is no admin
    override in access_control.py, and no document key is wrapped for the
    admin, so it is impossible even with direct DB access.
"""
from datetime import datetime, timedelta, timezone

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from ..db import get_db
from ..security import audit
from ..security.access_control import authorize_system
from ..services import documents as docs
from ..services import users
from . import login_required

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/users")
@login_required
def users_page():
    authorize_system(g.user, "manage_users")
    rows = get_db().execute("SELECT id, username, system_role, is_active, locked_until, created_at "
                            "FROM users ORDER BY created_at").fetchall()
    return render_template("admin/users.html", users=rows)


@bp.route("/users/<user_id>/active", methods=["POST"])
@login_required
def set_active(user_id):
    authorize_system(g.user, "manage_users")
    try:
        users.set_active(get_db(), g.user, user_id, request.form.get("active") == "1")
        flash("User updated.", "info")
    except users.UserError as exc:
        flash(str(exc), "error")
    return redirect(url_for("admin.users_page"))


@bp.route("/users/<user_id>/role", methods=["POST"])
@login_required
def set_role(user_id):
    authorize_system(g.user, "manage_users")
    try:
        users.set_system_role(get_db(), g.user, user_id, request.form.get("role", ""))
        flash("Role updated.", "info")
    except users.UserError as exc:
        flash(str(exc), "error")
    return redirect(url_for("admin.users_page"))


@bp.route("/audit")
@login_required
def audit_page():
    authorize_system(g.user, "view_audit")
    conn = get_db()
    # Filters (all parameterised)
    where, params = [], []
    for field in ("actor_username", "action", "outcome", "target_id"):
        value = request.args.get(field, "").strip()
        if value:
            where.append(f"{field} LIKE ?")   # field name comes from our fixed tuple, not the user
            params.append(f"%{value}%")
    sql = "SELECT * FROM audit_log" + (" WHERE " + " AND ".join(where) if where else "") + \
          " ORDER BY seq DESC LIMIT 300"
    rows = conn.execute(sql, params).fetchall()

    # ---- Suspicious-activity indicators (Part 1.5 Q5) -------------------
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    suspicious = conn.execute(
        """SELECT COALESCE(actor_username, json_extract(details, '$.username_attempted')) AS who,
                  SUM(action = 'auth.login' AND outcome = 'failure')     AS failed_logins,
                  SUM(action LIKE '%access_denied' AND outcome = 'denied') AS denied,
                  SUM(action = 'document.integrity_failure')             AS integrity_failures,
                  SUM(action = 'document.download')                      AS downloads,
                  SUM(action = 'security.csrf_rejected')                 AS csrf
           FROM audit_log WHERE ts >= ? GROUP BY who
           HAVING failed_logins >= 3 OR denied >= 3 OR integrity_failures >= 1 OR downloads >= 20 OR csrf >= 1
           ORDER BY denied DESC, failed_logins DESC""", (since,)).fetchall()
    audit.record("admin.audit_view", target_type="system", details={"filters": len(params)})
    return render_template("admin/audit.html", rows=rows, suspicious=suspicious, args=request.args)


@bp.route("/audit/verify", methods=["POST"])
@login_required
def audit_verify():
    authorize_system(g.user, "verify_audit")
    from flask import current_app
    result = audit.verify_chain(get_db(), current_app.config["SERVER_SECRETS"]["audit_hmac"],
                                current_app.config["AUDIT_ANCHOR_FILE"])
    audit.record("admin.audit_verify", "success" if result["ok"] else "failure", target_type="system",
                 details={"checked": result["checked"], "problems": len(result["problems"])})
    return render_template("admin/audit_verify.html", result=result)


@bp.route("/integrity", methods=["GET", "POST"])
@login_required
def integrity():
    authorize_system(g.user, "integrity_scan")
    results = docs.integrity_scan(get_db()) if request.method == "POST" else None
    return render_template("admin/integrity.html", results=results)
