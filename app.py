from flask import Flask, render_template, request, redirect, url_for, make_response, g
import json
import os
import re
import time
import secrets
import bcrypt
import config
from security_logger import security_log
import uuid
from werkzeug.utils import secure_filename
from encryption import encrypt_file, decrypt_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import html

#TODO Rate limiting: Max 10 login attempts per IP per minute

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=[],
    headers_enabled=True,
    swallow_errors=False
)

@limiter.request_filter
def exempt_check():
    return False

app.config["RATELIMIT_STORAGE_URI"] = "memory://"
app.config["RATELIMIT_HEADERS_ENABLED"] = True

# ── security headers ─────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]     = "geolocation=(), microphone=(), camera=()"
    return response

# ── helpers ──────────────────────────────────────────────
def load_json(filepath):
    if not os.path.exists(filepath):
        return {}
    with open(filepath, "r") as f:
        content = f.read().strip()
        if not content:
            return {}
        return json.loads(content)

def save_json(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

# ── validation ───────────────────────────────────────────
def sanitize_input(value):
    """Escape HTML special characters to prevent XSS"""
    if not value:
        return value
    return html.escape(value.strip())

def validate_username(username):
    if not username:
        return False, "Username is required"
    if not 3 <= len(username) <= 20:
        return False, "Username must be 3-20 characters"
    if not re.match(r'^[\w]+$', username):
        return False, "Username can only contain letters, numbers, underscore"
    return True, ""

def validate_email(email):
    if not email:
        return False, "Email is required"
    if len(email) > 254:
        return False, "Email is too long"
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return False, "Invalid email format"
    return True, ""

def validate_password(password):
    if not password:
        return False, "Password is required"
    if len(password) > 128:
        return False, "Password is too long"
    if len(password) < config.MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least 1 uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least 1 lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least 1 number"
    if not re.search(r'[!@#$%^&*]', password):
        return False, "Password must contain at least 1 special character (!@#$%^&*)"
    return True, ""

# ── session management ───────────────────────────────────
def create_session(user_id):
    token = secrets.token_urlsafe(32)
    sessions = load_json(config.SESSIONS_FILE)
    sessions[token] = {
        "user_id":       user_id,
        "created_at":    time.time(),
        "last_activity": time.time()
    }
    save_json(config.SESSIONS_FILE, sessions)
    security_log.log_event("SESSION_CREATED", user_id=user_id)
    return token

def validate_session(token):
    if not token:
        return None
    sessions = load_json(config.SESSIONS_FILE)
    if token not in sessions:
        return None
    session = sessions[token]
    if time.time() - session["last_activity"] > config.SESSION_TIMEOUT:
        del sessions[token]
        save_json(config.SESSIONS_FILE, sessions)
        security_log.log_event("SESSION_EXPIRED", user_id=session["user_id"])
        return None
    session["last_activity"] = time.time()
    sessions[token] = session
    save_json(config.SESSIONS_FILE, sessions)
    return session

def destroy_session(token):
    sessions = load_json(config.SESSIONS_FILE)
    if token in sessions:
        user_id = sessions[token].get("user_id")
        del sessions[token]
        save_json(config.SESSIONS_FILE, sessions)
        security_log.log_event("SESSION_DESTROYED", user_id=user_id)

# ── auth helpers ─────────────────────────────────────────
def get_current_user():
    token = request.cookies.get("session_token")
    session = validate_session(token)
    if not session:
        return None
    users = load_json(config.USERS_FILE)
    return users.get(session["user_id"])

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def require_role(role):
    from functools import wraps
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user or user["role"] != role:
                security_log.log_event(
                    "ACCESS_DENIED",
                    user_id=user["username"] if user else None,
                    details={"resource": request.path, "reason": "Insufficient privileges"},
                    severity="WARNING"
                )
                return render_template("error.html",
                    error="Access denied: insufficient permissions"), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ── load user into g on every request ────────────────────
@app.before_request
def load_user():
    g.user = get_current_user()

# ── routes ───────────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if request.method == "POST":
        # Sanitize all inputs first
        username = sanitize_input(request.form.get("username", ""))
        email    = sanitize_input(request.form.get("email", ""))
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        valid, msg = validate_username(username)
        if not valid:
            security_log.log_event("VALIDATION_FAILED",
                details={"field": "username", "reason": msg}, severity="WARNING")
            return render_template("register.html", error=msg)

        valid, msg = validate_email(email)
        if not valid:
            security_log.log_event("VALIDATION_FAILED",
                details={"field": "email", "reason": msg}, severity="WARNING")
            return render_template("register.html", error=msg)

        valid, msg = validate_password(password)
        if not valid:
            security_log.log_event("VALIDATION_FAILED",
                details={"field": "password", "reason": msg}, severity="WARNING")
            return render_template("register.html", error=msg)

        if password != confirm:
            return render_template("register.html", error="Passwords do not match")

        users = load_json(config.USERS_FILE)

        if username in users:
            return render_template("register.html", error="Username already taken")
        if any(u["email"] == email for u in users.values()):
            return render_template("register.html", error="Email already registered")

        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))

        users[username] = {
            "username":        username,
            "email":           email,
            "password_hash":   hashed.decode("utf-8"),
            "role":            "user",
            "created_at":      time.time(),
            "failed_attempts": 0,
            "locked_until":    None
        }
        save_json(config.USERS_FILE, users)
        security_log.log_event("USER_REGISTERED", user_id=username,
            details={"email": email})
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        users = load_json(config.USERS_FILE)

        if username not in users:
            security_log.log_event("LOGIN_FAILED",
                details={"username": username, "reason": "User not found"},
                severity="WARNING")
            return render_template("login.html", error="Invalid credentials")

        user = users[username]

        # Check lockout
        if user["locked_until"] and time.time() < user["locked_until"]:
            mins = int((user["locked_until"] - time.time()) / 60) + 1
            security_log.log_event("LOGIN_BLOCKED", user_id=username,
                details={"reason": "Account locked"}, severity="WARNING")
            return render_template("login.html",  
                error=f"Account locked. Try again in {mins} minute(s)")

        # Check password
        if not bcrypt.checkpw(password.encode("utf-8"),
                              user["password_hash"].encode("utf-8")):
            user["failed_attempts"] += 1
            if user["failed_attempts"] >= config.MAX_FAILED_ATTEMPTS:
                user["locked_until"] = time.time() + config.LOCKOUT_DURATION
                user["failed_attempts"] = 0
                save_json(config.USERS_FILE, users)
                security_log.log_event("ACCOUNT_LOCKED", user_id=username,
                    details={"reason": "5 failed login attempts"}, severity="ERROR")
                return render_template("login.html",
                    error="Too many failed attempts. Account locked for 15 minutes.")
            save_json(config.USERS_FILE, users)
            remaining = config.MAX_FAILED_ATTEMPTS - user["failed_attempts"]
            security_log.log_event("LOGIN_FAILED", user_id=username,
                details={"reason": "Wrong password"}, severity="WARNING")
            return render_template("login.html",
                error=f"Invalid credentials. {remaining} attempt(s) remaining.")

        # Success
        user["failed_attempts"] = 0
        user["locked_until"]    = None
        save_json(config.USERS_FILE, users)

        token = create_session(username)
        security_log.log_event("LOGIN_SUCCESS", user_id=username)

        response = make_response(redirect(url_for("dashboard")))
        response.set_cookie(
            "session_token", token,
            httponly=True,
            samesite="Strict",
            max_age=config.SESSION_TIMEOUT
        )
        return response

    return render_template("login.html")

@app.route("/dashboard")
@require_auth
def dashboard():
    return render_template("dashboard.html", user=g.user)

@app.route("/admin")
@require_auth
@require_role("admin")
def admin_dashboard():
    users     = load_json(config.USERS_FILE)
    documents = load_json(config.DOCUMENTS_FILE)
    return render_template("admin.html", users=users, documents=documents)

@app.route("/admin/delete_user/<username>")
@require_auth
@require_role("admin")
def delete_user(username):
    users = load_json(config.USERS_FILE)

    if username not in users:
        return render_template("error.html", error="User not found"), 404

    if username == "admin":
        return render_template("error.html", error="Cannot delete admin account"), 403

    if username == "guest":
        return render_template("error.html", error="Cannot delete guest account"), 403

    del users[username]
    save_json(config.USERS_FILE, users)

    security_log.log_event("USER_DELETED", user_id=g.user["username"],
        details={"deleted_user": username})

    return redirect(url_for("admin_dashboard"))

@app.route("/admin/change_role/<username>", methods=["POST"])
@require_auth
@require_role("admin")
def change_role(username):
    users = load_json(config.USERS_FILE)

    if username not in users:
        return render_template("error.html", error="User not found"), 404

    if username == "admin":
        return render_template("error.html", error="Cannot change admin role"), 403

    new_role = request.form.get("role")
    if new_role not in ("admin", "user", "guest"):
        return render_template("error.html", error="Invalid role"), 400

    old_role = users[username]["role"]
    users[username]["role"] = new_role
    save_json(config.USERS_FILE, users)

    security_log.log_event("ROLE_CHANGED", user_id=g.user["username"],
        details={"target_user": username, "old_role": old_role, "new_role": new_role})

    return redirect(url_for("admin_dashboard"))

@app.route("/logout")
def logout():
    token = request.cookies.get("session_token")
    destroy_session(token)
    response = make_response(redirect(url_for("login")))
    response.delete_cookie("session_token")
    return response

@app.route("/guest")
def guest_login():
    """Create a temporary guest session"""
    token = create_session("guest")
    response = make_response(redirect(url_for("documents")))
    response.set_cookie(
        "session_token", token,
        httponly=True,
        samesite="Strict",
        max_age=3600
    )
    return response

# ── document helpers ─────────────────────────────────────
def allowed_file(filename):
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in config.ALLOWED_EXTENSIONS

# ── document routes ──────────────────────────────────────
@app.route("/documents")
@require_auth
def documents():
    all_docs = load_json(config.DOCUMENTS_FILE)
    username = g.user["username"]

    # Show docs owned by user or shared with them
    user_docs = {
        doc_id: doc for doc_id, doc in all_docs.items()
        if doc["owner"] == username
        or username in doc.get("shared_with", {})
        or g.user["role"] == "admin"
    }
    return render_template("documents.html", documents=user_docs, user=g.user)

# Allowed MIME types matching our extensions
ALLOWED_MIMES = {
    "application/pdf",
    "text/plain",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "image/png",
    "image/jpeg"
}

@app.route("/documents/upload", methods=["GET", "POST"])
@require_auth
def upload_document():
    if request.method == "POST":
        if "file" not in request.files:
            return render_template("upload.html", error="No file selected")

        file = request.files["file"]

        if file.filename == "":
            return render_template("upload.html", error="No file selected")

        if not allowed_file(file.filename):
            security_log.log_event("UPLOAD_REJECTED", user_id=g.user["username"],
                details={"filename": file.filename, "reason": "Invalid extension"},
                severity="WARNING")
            return render_template("upload.html",
                error=f"File type not allowed. Allowed: {', '.join(config.ALLOWED_EXTENSIONS)}")

        # Check MIME type
        if file.mimetype not in ALLOWED_MIMES:
            security_log.log_event("UPLOAD_REJECTED", user_id=g.user["username"],
                details={"filename": file.filename, "reason": "Invalid MIME type",
                         "mime": file.mimetype},
                severity="WARNING")
            return render_template("upload.html",
                error=f"Invalid file type detected: {file.mimetype}")

        # Read and check file size
        file_data = file.read()
        if len(file_data) > config.MAX_FILE_SIZE:
            return render_template("upload.html", error="File too large (max 16MB)")

        filename  = secure_filename(file.filename)
        doc_id    = str(uuid.uuid4())
        encrypted = encrypt_file(file_data)

        os.makedirs(config.UPLOADS_DIR, exist_ok=True)
        save_path = os.path.join(config.UPLOADS_DIR, doc_id + ".enc")
        with open(save_path, "wb") as f:
            f.write(encrypted)

        docs = load_json(config.DOCUMENTS_FILE)
        docs[doc_id] = {
            "doc_id":      doc_id,
            "filename":    filename,
            "owner":       g.user["username"],
            "shared_with": {},
            "uploaded_at": time.time(),
            "versions":    [{"version": 1, "uploaded_at": time.time()}]
        }
        save_json(config.DOCUMENTS_FILE, docs)

        security_log.log_event("DOCUMENT_UPLOADED", user_id=g.user["username"],
            details={"filename": filename, "doc_id": doc_id})

        return redirect(url_for("documents"))

    return render_template("upload.html")

@app.route("/documents/download/<doc_id>")
@require_auth
def download_document(doc_id):
    docs     = load_json(config.DOCUMENTS_FILE)
    username = g.user["username"]

    if doc_id not in docs:
        return render_template("error.html", error="Document not found"), 404

    doc = docs[doc_id]

    # Check access
    if doc["owner"] != username \
       and username not in doc.get("shared_with", {}) \
       and g.user["role"] != "admin":
        security_log.log_event("ACCESS_DENIED", user_id=username,
            details={"doc_id": doc_id, "reason": "Not authorized"},
            severity="WARNING")
        return render_template("error.html", error="Access denied"), 403

    # Decrypt and send file
    enc_path = os.path.join(config.UPLOADS_DIR, doc_id + ".enc")
    with open(enc_path, "rb") as f:
        encrypted = f.read()

    decrypted = decrypt_file(encrypted)

    security_log.log_event("DOCUMENT_DOWNLOADED", user_id=username,
        details={"doc_id": doc_id, "filename": doc["filename"]})

    from flask import send_file
    import io
    return send_file(
        io.BytesIO(decrypted),
        download_name=doc["filename"],
        as_attachment=True
    )

@app.route("/documents/share/<doc_id>", methods=["GET", "POST"])
@require_auth
def share_document(doc_id):
    docs     = load_json(config.DOCUMENTS_FILE)
    username = g.user["username"]

    if doc_id not in docs:
        return render_template("error.html", error="Document not found"), 404

    doc = docs[doc_id]

    # Only owner or admin can share
    if doc["owner"] != username and g.user["role"] != "admin":
        return render_template("error.html", error="Only the owner can share this document"), 403

    if request.method == "POST":
        share_with = request.form.get("username", "").strip()
        role       = request.form.get("role", "viewer")

        if role not in ("viewer", "editor"):
            return render_template("share.html", doc=doc,
                error="Invalid role — must be viewer or editor")

        users = load_json(config.USERS_FILE)
        if share_with not in users:
            return render_template("share.html", doc=doc,
                error="User not found")

        if share_with == username:
            return render_template("share.html", doc=doc,
                error="You cannot share a document with yourself")

        doc["shared_with"][share_with] = role
        save_json(config.DOCUMENTS_FILE, docs)

        security_log.log_event("DOCUMENT_SHARED", user_id=username,
            details={"doc_id": doc_id, "shared_with": share_with, "role": role})

        return redirect(url_for("documents"))

    return render_template("share.html", doc=doc)

@app.route("/documents/delete/<doc_id>")
@require_auth
def delete_document(doc_id):
    docs     = load_json(config.DOCUMENTS_FILE)
    username = g.user["username"]

    if doc_id not in docs:
        return render_template("error.html", error="Document not found"), 404

    doc = docs[doc_id]

    # Only owner or admin can delete
    if doc["owner"] != username and g.user["role"] != "admin":
        return render_template("error.html", error="Only the owner can delete this document"), 403

    # Delete encrypted file
    enc_path = os.path.join(config.UPLOADS_DIR, doc_id + ".enc")
    if os.path.exists(enc_path):
        os.remove(enc_path)

    del docs[doc_id]
    save_json(config.DOCUMENTS_FILE, docs)

    security_log.log_event("DOCUMENT_DELETED", user_id=username,
        details={"doc_id": doc_id, "filename": doc["filename"]})

    return redirect(url_for("documents"))

@app.route("/documents/edit/<doc_id>", methods=["GET", "POST"])
@require_auth
@require_role("user")
def edit_document(doc_id):
    docs     = load_json(config.DOCUMENTS_FILE)
    username = g.user["username"]

    if doc_id not in docs:
        return render_template("error.html", error="Document not found"), 404

    doc = docs[doc_id]

    # Only owner or admin can edit
    if doc["owner"] != username and g.user["role"] != "admin":
        security_log.log_event("ACCESS_DENIED", user_id=username,
            details={"doc_id": doc_id, "reason": "Not owner"},
            severity="WARNING")
        return render_template("error.html", error="Only the owner can edit this document"), 403

    if request.method == "POST":
        if "file" not in request.files:
            return render_template("edit.html", doc=doc, error="No file selected")

        file = request.files["file"]

        if file.filename == "":
            return render_template("edit.html", doc=doc, error="No file selected")

        if not allowed_file(file.filename):
            return render_template("edit.html", doc=doc,
                error=f"File type not allowed. Allowed: {', '.join(config.ALLOWED_EXTENSIONS)}")

        # Check MIME type
        if file.mimetype not in ALLOWED_MIMES:
            return render_template("edit.html", doc=doc,
                error=f"Invalid file type detected: {file.mimetype}")

        # Read and check size
        file_data = file.read()
        if len(file_data) > config.MAX_FILE_SIZE:
            return render_template("edit.html", doc=doc, error="File too large (max 16MB)")

        # Encrypt and overwrite old file
        filename  = secure_filename(file.filename)
        encrypted = encrypt_file(file_data)

        save_path = os.path.join(config.UPLOADS_DIR, doc_id + ".enc")
        with open(save_path, "wb") as f:
            f.write(encrypted)

        # Update metadata and increment version
        current_version = len(doc["versions"]) + 1
        doc["filename"] = filename
        doc["versions"].append({
            "version":     current_version,
            "uploaded_at": time.time(),
            "updated_by":  username
        })
        docs[doc_id] = doc
        save_json(config.DOCUMENTS_FILE, docs)

        security_log.log_event("DOCUMENT_EDITED", user_id=username,
            details={"doc_id": doc_id, "filename": filename,
                     "version": current_version})

        return redirect(url_for("documents"))

    return render_template("edit.html", doc=doc)

if __name__ == "__main__":
    app.run(
        ssl_context=('cert.pem', 'key.pem'),
        host='0.0.0.0',
        port=5000,
        debug=True
    )