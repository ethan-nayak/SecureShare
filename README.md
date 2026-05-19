# SecureShare

### Computer Security — Secure Web Application Project

**Authors:** Ethan Nayak & Krystian Bochenko  
**Professor:** Prof. Rakesh Kushwaha

A Flask-based secure document sharing system with encrypted file storage, role-based access control, and comprehensive security controls.

---

## Features

- User registration and login with secure password hashing
- Upload and download encrypted documents
- Share documents with specific users (viewer/editor roles)
- Role-based access control (Admin, User, Guest)
- Document versioning and audit trail
- Security headers, session management, and rate limiting
- Full security event logging

---

## Screenshots

> _Add screenshots here_

---

## Requirements

- Python 3.10+
- pip
- Git

---

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/ethan-nayak/SecureShare.git
cd SecureShare
```

### 2. Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Initialize Data Files

```bash
python3 -c "
import json, os
os.makedirs('data', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('uploads', exist_ok=True)
for f in ['data/users.json', 'data/sessions.json', 'data/documents.json']:
    with open(f, 'w') as file:
        json.dump({}, file)
open('logs/security.log', 'w').close()
open('logs/access.log', 'w').close()
print('Done!')
"
```

### 5. Generate TLS Certificate

```bash
pip install pyopenssl
python3 -c "
from OpenSSL import crypto
k = crypto.PKey()
k.generate_key(crypto.TYPE_RSA, 4096)
cert = crypto.X509()
cert.get_subject().CN = 'localhost'
cert.set_serial_number(1)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(365*24*60*60)
cert.set_issuer(cert.get_subject())
cert.set_pubkey(k)
cert.sign(k, 'sha256')
open('cert.pem', 'wb').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
open('key.pem', 'wb').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
print('Done!')
"
```

### 6. Create Admin Account

```bash
python3 -c "
import json, bcrypt, time, getpass
with open('data/users.json', 'r') as f:
    users = json.load(f)
password = getpass.getpass('Set admin password: ').encode()
hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
users['admin'] = {
    'username': 'admin',
    'email': 'admin@example.com',
    'password_hash': hashed.decode('utf-8'),
    'role': 'admin',
    'created_at': time.time(),
    'failed_attempts': 0,
    'locked_until': None
}
users['guest'] = {
    'username': 'guest',
    'email': 'guest@example.com',
    'password_hash': '',
    'role': 'guest',
    'created_at': time.time(),
    'failed_attempts': 0,
    'locked_until': None
}
with open('data/users.json', 'w') as f:
    json.dump(users, f, indent=2)
print('Admin and Guest accounts created!')
"
```

### 7. Run the App

```bash
python3 app.py
```

Then open your browser and go to: **https://127.0.0.1:5000**

> Your browser will show a security warning because the certificate is self-signed. This is normal for development. Click **Advanced → Proceed to 127.0.0.1** to continue.

---

## Default Accounts

| Username | Password | Role |
|----------|----------|------|
| admin | _(set during setup)_ | Admin |
| guest | _(no password — use guest link)_ | Guest |

Register a new account for regular user access.

---

## Testing the App

### Manual Testing

1. **Register** — go to `/register`, create a username and strong password
2. **Login** — go to `/login` with your credentials
3. **Upload a document** — go to Documents → Upload New Document (pdf, txt, docx, png, jpg — max 16MB)
4. **Share a document** — click Share next to any document you own, enter a username and role
5. **Guest access** — click "Continue as Guest" on the login page
6. **Admin panel** — login as admin, click Admin Panel to manage users and documents

### Automated Tests

```bash
pip install pytest
pytest tests/script.py -v
```

All 11 tests should pass.

---

## Security Features

| Feature | Implementation |
|---------|----------------|
| Password hashing | bcrypt with cost factor 12 |
| Account lockout | 5 failed attempts → 15 min lockout |
| Rate limiting | 10 login attempts per IP per minute |
| Session management | Secure tokens with 30-minute timeout |
| Cookie security | HttpOnly, Secure, SameSite=Strict |
| File encryption | Fernet (AES-128-CBC) |
| Transport security | HTTPS/TLS with self-signed certificate |
| Input validation | Whitelist validation + html.escape |
| Security headers | CSP, HSTS, X-Frame-Options, and more |
| Logging | All security events logged to logs/security.log |

---

## Project Structure

```
SecureShare/
├── README.md               # This file
├── requirements.txt        # Python dependencies
├── app.py                  # Main application
├── config.py               # Configuration settings
├── encryption.py           # Fernet file encryption
├── security_logger.py      # Security event logging
├── data/
│   ├── users.json          # User accounts
│   ├── sessions.json       # Active sessions
│   └── documents.json      # Document metadata
├── logs/
│   └── security.log        # Security events
├── static/
├── templates/
├── docs/
│   ├── security_design.pdf
│   └── pentest_report.pdf
└── tests/
    └── script.py
```

---

## Reset the App

To clear all data and start fresh:

```bash
python3 -c "
import json, os, shutil
for f in ['data/users.json', 'data/sessions.json', 'data/documents.json']:
    with open(f, 'w') as file:
        json.dump({}, file)
if os.path.exists('uploads'):
    shutil.rmtree('uploads')
    os.makedirs('uploads')
open('logs/security.log', 'w').close()
print('Reset complete!')
"
```

Then re-run Step 6 to recreate the admin account.

---

## View Security Logs

```bash
cat logs/security.log
```
