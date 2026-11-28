"""
app/routes/documents.py
=======================
Document pages: dashboard, upload, details, download, update, verify,
share, revoke, delete.

Notice there are NO permission checks written here — on purpose. Every
service function performs its own authorize_document() call, so a route
can never "forget" a check (fail-safe design).
"""
import io

from flask import (Blueprint, flash, g, redirect, render_template, request,
                   send_file, url_for)

from ..db import get_db
from ..services import documents as docs
from . import login_required

bp = Blueprint("documents", __name__)


@bp.route("/documents")
@login_required
def dashboard():
    items = docs.list_for_user(get_db(), g.user, g.keys)
    return render_template("documents/dashboard.html",
                           owned=[d for d in items if d["role"] == "owner"],
                           shared=[d for d in items if d["role"] != "owner"])


@bp.route("/documents/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if f is None or not f.filename:
            flash("Choose a file to upload.", "error")
            return render_template("documents/upload.html"), 400
        try:
            doc_id = docs.upload(get_db(), g.user, g.keys, f.filename, f.mimetype, f.read())
        except docs.DocumentError as exc:
            flash(str(exc), "error")
            return render_template("documents/upload.html"), 400
        flash("Uploaded, encrypted and signed.", "info")
        return redirect(url_for("documents.detail", doc_id=doc_id))
    return render_template("documents/upload.html")


@bp.route("/documents/<doc_id>")
@login_required
def detail(doc_id):
    d = docs.get_details(get_db(), g.user, g.keys, doc_id)
    return render_template("documents/detail.html", doc=d)


@bp.route("/documents/<doc_id>/download")
@login_required
def download(doc_id):
    try:
        filename, data = docs.download(get_db(), g.user, g.keys, doc_id)
    except docs.DocumentError as exc:
        return render_template("error.html", code=409, message=str(exc)), 409
    # Sent from memory (no temporary plaintext file on the server), forced
    # as an attachment with a neutral MIME type -> browser won't render
    # uploaded HTML/JS (prevents stored XSS through documents).
    return send_file(io.BytesIO(data), as_attachment=True, download_name=filename,
                     mimetype="application/octet-stream", max_age=0)


@bp.route("/documents/<doc_id>/verify", methods=["POST"])
@login_required
def verify(doc_id):
    report = docs.verify(get_db(), g.user, g.keys, doc_id)
    d = docs.get_details(get_db(), g.user, g.keys, doc_id)
    return render_template("documents/detail.html", doc=d, report=report)


@bp.route("/documents/<doc_id>/update", methods=["POST"])
@login_required
def update(doc_id):
    f = request.files.get("file")
    if f is None or not f.filename:
        flash("Choose a file.", "error")
        return redirect(url_for("documents.detail", doc_id=doc_id))
    try:
        v = docs.update(get_db(), g.user, g.keys, doc_id, f.filename, f.mimetype, f.read())
        flash(f"New version {v} uploaded and signed.", "info")
    except docs.DocumentError as exc:
        flash(str(exc), "error")
    return redirect(url_for("documents.detail", doc_id=doc_id))


@bp.route("/documents/<doc_id>/share", methods=["POST"])
@login_required
def share(doc_id):
    try:
        docs.share(get_db(), g.user, g.keys, doc_id, request.form.get("username", ""),
                   request.form.get("role", ""), request.form.get("expires_days") or None)
        flash("Access granted.", "info")
    except (docs.DocumentError, ValueError) as exc:
        flash(str(exc), "error")
    return redirect(url_for("documents.detail", doc_id=doc_id))


@bp.route("/documents/<doc_id>/revoke", methods=["POST"])
@login_required
def revoke(doc_id):
    try:
        docs.revoke(get_db(), g.user, g.keys, doc_id, request.form.get("user_id", ""))
        flash("Access revoked and document re-encrypted with a new key.", "info")
    except docs.DocumentError as exc:
        flash(str(exc), "error")
    return redirect(url_for("documents.detail", doc_id=doc_id))


@bp.route("/documents/<doc_id>/delete", methods=["POST"])
@login_required
def delete(doc_id):
    docs.delete(get_db(), g.user, doc_id)
    flash("Document deleted (blob wiped, keys destroyed).", "info")
    return redirect(url_for("documents.dashboard"))
