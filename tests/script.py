import sys
import os

# Must set environment variables BEFORE importing app
os.environ['RATELIMIT_ENABLED'] = 'False'

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import app as application
import pytest

application.app.config['TESTING'] = True
application.app.config['RATELIMIT_ENABLED'] = False
application.app.config['WTF_CSRF_ENABLED'] = False

client = application.app.test_client()
application.limiter.enabled = False  # disable limiter directly

# ── Authentication Tests ──────────────────────────────────
def test_register_weak_password():
    res = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@test.com',
        'password': 'weak',
        'confirm_password': 'weak'
    })
    assert b'Password' in res.data

def test_register_invalid_username():
    res = client.post('/register', data={
        'username': 'ab',
        'email': 'test@test.com',
        'password': 'SecurePass1!',
        'confirm_password': 'SecurePass1!'
    })
    assert b'3-20' in res.data

def test_register_mismatched_passwords():
    res = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@test.com',
        'password': 'SecurePass1!',
        'confirm_password': 'DifferentPass1!'
    })
    assert b'match' in res.data

def test_login_invalid_credentials():
    res = client.post('/login', data={
        'username': 'nonexistent',
        'password': 'wrongpassword'
    })
    assert b'Invalid' in res.data

def test_dashboard_requires_auth():
    res = client.get('/dashboard')
    assert res.status_code == 302

def test_admin_requires_auth():
    res = client.get('/admin')
    assert res.status_code == 302

def test_documents_requires_auth():
    res = client.get('/documents')
    assert res.status_code == 302

# ── Security Header Tests ─────────────────────────────────
def test_security_headers():
    res = client.get('/login')
    assert 'X-Frame-Options' in res.headers
    assert 'X-Content-Type-Options' in res.headers
    assert 'Content-Security-Policy' in res.headers
    assert 'X-XSS-Protection' in res.headers
    assert 'Referrer-Policy' in res.headers
    assert 'Permissions-Policy' in res.headers
    assert res.headers['X-Frame-Options'] == 'DENY'
    assert res.headers['X-Content-Type-Options'] == 'nosniff'

# ── Input Validation Tests ────────────────────────────────
def test_xss_in_username():
    res = client.post('/register', data={
        'username': '<img src=x>',
        'email': 'test@test.com',
        'password': 'SecurePass1!',
        'confirm_password': 'SecurePass1!'
    })
    assert b'letters, numbers' in res.data

def test_password_no_uppercase():
    res = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@test.com',
        'password': 'alllowercase1!',
        'confirm_password': 'alllowercase1!'
    })
    assert b'uppercase' in res.data

def test_password_no_special_char():
    res = client.post('/register', data={
        'username': 'testuser2',
        'email': 'test2@test.com',
        'password': 'NoSpecialChar12',
        'confirm_password': 'NoSpecialChar12'
    })
    assert b'special' in res.data

if __name__ == '__main__':
    pytest.main([__file__, '-v'])