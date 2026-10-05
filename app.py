"""
Cloud File Storage System
--------------------------
A Flask-based web application that simulates a personal cloud storage
service. Users can register, log in, upload files, organize them into
folders, download/preview/delete/rename/share files, and monitor their
storage quota — all backed by SQLite (metadata) and the local filesystem
(actual file bytes), mirroring how a real object-storage cloud service
separates metadata from blob storage.

Run:
    pip install -r requirements.txt
    python app.py

Then visit http://127.0.0.1:5000
"""

import os
import io
import uuid
import hashlib
import mimetypes
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, send_from_directory, abort, jsonify, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_ROOT = os.path.join(BASE_DIR, "uploads")
DATABASE = os.path.join(BASE_DIR, "instance", "cloud_storage.db")

# Default quota per user, in bytes (500 MB)
DEFAULT_QUOTA_BYTES = 500 * 1024 * 1024

# Files larger than this are rejected outright (2 GB hard cap)
MAX_CONTENT_LENGTH = 2 * 1024 * 1024 * 1024

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("CLOUD_STORAGE_SECRET", "dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

os.makedirs(UPLOAD_ROOT, exist_ok=True)
os.makedirs(os.path.dirname(DATABASE), exist_ok=True)


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            quota_bytes   INTEGER NOT NULL DEFAULT 524288000,
            is_admin      INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS folders (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id    INTEGER NOT NULL,
            parent_id   INTEGER,
            name        TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS files (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id      INTEGER NOT NULL,
            folder_id     INTEGER,
            original_name TEXT NOT NULL,
            stored_name   TEXT NOT NULL UNIQUE,
            size_bytes    INTEGER NOT NULL,
            mime_type     TEXT,
            checksum      TEXT,
            uploaded_at   TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS share_links (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id     INTEGER NOT NULL,
            token       TEXT UNIQUE NOT NULL,
            expires_at  TEXT,
            created_at  TEXT NOT NULL,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS activity_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            action      TEXT NOT NULL,
            detail      TEXT,
            created_at  TEXT NOT NULL
        );
        """
    )
    db.commit()
    db.close()


def log_activity(action, detail=""):
    db = get_db()
    db.execute(
        "INSERT INTO activity_log (user_id, action, detail, created_at) VALUES (?, ?, ?, ?)",
        (session.get("user_id"), action, detail, datetime.utcnow().isoformat()),
    )
    db.commit()


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def current_user():
    if "user_id" not in session:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


def user_storage_dir(user_id):
    path = os.path.join(UPLOAD_ROOT, str(user_id))
    os.makedirs(path, exist_ok=True)
    return path


def used_bytes(user_id):
    db = get_db()
    row = db.execute(
        "SELECT COALESCE(SUM(size_bytes), 0) AS total FROM files WHERE owner_id = ?",
        (user_id,),
    ).fetchone()
    return row["total"]


def human_size(num_bytes):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}" if unit != "B" else f"{int(num_bytes)} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"


app.jinja_env.filters["human_size"] = human_size


# --------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(url_for("register"))

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, email, password_hash, quota_bytes, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (username, email, generate_password_hash(password),
                 DEFAULT_QUOTA_BYTES, datetime.utcnow().isoformat()),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username or email already taken.", "danger")
            return redirect(url_for("register"))

        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier),
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            log_activity("login", f"user {user['username']} logged in")
            return redirect(request.args.get("next") or url_for("dashboard"))

        flash("Invalid username/email or password.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    log_activity("logout")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Core file management routes
# --------------------------------------------------------------------------

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    folder_id = request.args.get("folder", type=int)
    user = current_user()

    folders = db.execute(
        "SELECT * FROM folders WHERE owner_id = ? AND parent_id IS ? ORDER BY name",
        (user["id"], folder_id),
    ).fetchall()

    files = db.execute(
        "SELECT * FROM files WHERE owner_id = ? AND folder_id IS ? ORDER BY uploaded_at DESC",
        (user["id"], folder_id),
    ).fetchall()

    breadcrumb = []
    walk = folder_id
    while walk:
        f = db.execute("SELECT * FROM folders WHERE id = ?", (walk,)).fetchone()
        if not f:
            break
        breadcrumb.insert(0, f)
        walk = f["parent_id"]

    used = used_bytes(user["id"])
    quota = user["quota_bytes"]
    percent_used = round((used / quota) * 100, 1) if quota else 0

    return render_template(
        "dashboard.html",
        folders=folders,
        files=files,
        breadcrumb=breadcrumb,
        current_folder=folder_id,
        used=used,
        quota=quota,
        percent_used=percent_used,
    )


@app.route("/folder/create", methods=["POST"])
@login_required
def create_folder():
    name = request.form.get("name", "").strip()
    parent_id = request.form.get("parent_id", type=int)
    if not name:
        flash("Folder name cannot be empty.", "danger")
        return redirect(url_for("dashboard", folder=parent_id))

    db = get_db()
    db.execute(
        "INSERT INTO folders (owner_id, parent_id, name, created_at) VALUES (?, ?, ?, ?)",
        (session["user_id"], parent_id, name, datetime.utcnow().isoformat()),
    )
    db.commit()
    log_activity("create_folder", name)
    return redirect(url_for("dashboard", folder=parent_id))


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    folder_id = request.form.get("folder_id", type=int)
    uploaded_files = request.files.getlist("files")
    user = current_user()

    if not uploaded_files or uploaded_files == [None]:
        flash("No file selected.", "danger")
        return redirect(url_for("dashboard", folder=folder_id))

    db = get_db()
    used = used_bytes(user["id"])
    quota = user["quota_bytes"]

    accepted, rejected = 0, []

    for file in uploaded_files:
        if not file or file.filename == "":
            continue

        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)

        if used + size > quota:
            rejected.append(file.filename)
            continue

        original_name = secure_filename(file.filename) or "unnamed_file"
        stored_name = f"{uuid.uuid4().hex}_{original_name}"
        dest_path = os.path.join(user_storage_dir(user["id"]), stored_name)

        hasher = hashlib.sha256()
        with open(dest_path, "wb") as out:
            chunk = file.read(8192)
            while chunk:
                hasher.update(chunk)
                out.write(chunk)
                chunk = file.read(8192)

        mime_type = mimetypes.guess_type(original_name)[0] or "application/octet-stream"

        db.execute(
            "INSERT INTO files (owner_id, folder_id, original_name, stored_name, "
            "size_bytes, mime_type, checksum, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (user["id"], folder_id, original_name, stored_name, size,
             mime_type, hasher.hexdigest(), datetime.utcnow().isoformat()),
        )
        db.commit()
        used += size
        accepted += 1
        log_activity("upload", original_name)

    if accepted:
        flash(f"{accepted} file(s) uploaded successfully.", "success")
    if rejected:
        flash(f"Skipped (quota exceeded): {', '.join(rejected)}", "warning")

    return redirect(url_for("dashboard", folder=folder_id))


@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    db = get_db()
    file_row = db.execute(
        "SELECT * FROM files WHERE id = ? AND owner_id = ?",
        (file_id, session["user_id"]),
    ).fetchone()
    if not file_row:
        abort(404)

    log_activity("download", file_row["original_name"])
    directory = user_storage_dir(session["user_id"])
    return send_from_directory(
        directory, file_row["stored_name"], as_attachment=True,
        download_name=file_row["original_name"]
    )


@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    db = get_db()
    file_row = db.execute(
        "SELECT * FROM files WHERE id = ? AND owner_id = ?",
        (file_id, session["user_id"]),
    ).fetchone()
    if not file_row:
        abort(404)

    path = os.path.join(user_storage_dir(session["user_id"]), file_row["stored_name"])
    if os.path.exists(path):
        os.remove(path)

    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    log_activity("delete", file_row["original_name"])
    flash(f"Deleted {file_row['original_name']}.", "info")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/rename/<int:file_id>", methods=["POST"])
@login_required
def rename_file(file_id):
    new_name = request.form.get("new_name", "").strip()
    db = get_db()
    file_row = db.execute(
        "SELECT * FROM files WHERE id = ? AND owner_id = ?",
        (file_id, session["user_id"]),
    ).fetchone()
    if not file_row or not new_name:
        abort(404)

    db.execute("UPDATE files SET original_name = ? WHERE id = ?", (new_name, file_id))
    db.commit()
    log_activity("rename", f"{file_row['original_name']} -> {new_name}")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
def create_share_link(file_id):
    db = get_db()
    file_row = db.execute(
        "SELECT * FROM files WHERE id = ? AND owner_id = ?",
        (file_id, session["user_id"]),
    ).fetchone()
    if not file_row:
        abort(404)

    token = uuid.uuid4().hex
    expires_at = (datetime.utcnow() + timedelta(days=7)).isoformat()
    db.execute(
        "INSERT INTO share_links (file_id, token, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (file_id, token, expires_at, datetime.utcnow().isoformat()),
    )
    db.commit()
    log_activity("share", file_row["original_name"])
    share_url = url_for("shared_download", token=token, _external=True)
    flash(f"Share link (valid 7 days): {share_url}", "success")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/s/<token>")
def shared_download(token):
    db = get_db()
    link = db.execute("SELECT * FROM share_links WHERE token = ?", (token,)).fetchone()
    if not link:
        abort(404)
    if link["expires_at"] and datetime.fromisoformat(link["expires_at"]) < datetime.utcnow():
        abort(410)

    file_row = db.execute("SELECT * FROM files WHERE id = ?", (link["file_id"],)).fetchone()
    if not file_row:
        abort(404)

    directory = user_storage_dir(file_row["owner_id"])
    return send_from_directory(
        directory, file_row["stored_name"], as_attachment=True,
        download_name=file_row["original_name"]
    )


@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "").strip()
    db = get_db()
    results = []
    if q:
        results = db.execute(
            "SELECT * FROM files WHERE owner_id = ? AND original_name LIKE ? "
            "ORDER BY uploaded_at DESC",
            (session["user_id"], f"%{q}%"),
        ).fetchall()
    return render_template("search.html", query=q, results=results)


# --------------------------------------------------------------------------
# Admin routes
# --------------------------------------------------------------------------

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    stats = []
    for u in users:
        stats.append({
            "user": u,
            "used": used_bytes(u["id"]),
            "file_count": db.execute(
                "SELECT COUNT(*) AS c FROM files WHERE owner_id = ?", (u["id"],)
            ).fetchone()["c"],
        })
    recent_activity = db.execute(
        "SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 50"
    ).fetchall()
    return render_template("admin.html", stats=stats, activity=recent_activity)


# --------------------------------------------------------------------------
# JSON API (for scripting / potential SPA frontend)
# --------------------------------------------------------------------------

@app.route("/api/files")
@login_required
def api_files():
    folder_id = request.args.get("folder", type=int)
    db = get_db()
    rows = db.execute(
        "SELECT id, original_name, size_bytes, mime_type, uploaded_at "
        "FROM files WHERE owner_id = ? AND folder_id IS ? ORDER BY uploaded_at DESC",
        (session["user_id"], folder_id),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/usage")
@login_required
def api_usage():
    user = current_user()
    used = used_bytes(user["id"])
    return jsonify({
        "used_bytes": used,
        "quota_bytes": user["quota_bytes"],
        "percent_used": round((used / user["quota_bytes"]) * 100, 1),
    })


# --------------------------------------------------------------------------
# Error handlers
# --------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Forbidden"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Not Found"), 404


@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", code=413, message="File too large"), 413


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def create_default_admin():
    db = sqlite3.connect(DATABASE)
    row = db.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
    if not row:
        db.execute(
            "INSERT INTO users (username, email, password_hash, quota_bytes, is_admin, created_at) "
            "VALUES (?, ?, ?, ?, 1, ?)",
            ("admin", "admin@cloudstorage.local", generate_password_hash("admin123"),
             DEFAULT_QUOTA_BYTES * 10, datetime.utcnow().isoformat()),
        )
        db.commit()
        print("Default admin created -> username: admin / password: admin123")
    db.close()


if __name__ == "__main__":
    init_db()
    create_default_admin()
    app.run(...)
