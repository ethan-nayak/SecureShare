import os

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-later")
DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")
DOCUMENTS_FILE = os.path.join(DATA_DIR, "documents.json")
UPLOADS_DIR = "uploads"

# Security settings
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 900
SESSION_TIMEOUT = 1800
MIN_PASSWORD_LENGTH = 12

# Upload settings
ALLOWED_EXTENSIONS = {"pdf", "txt", "docx", "png", "jpg"}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB