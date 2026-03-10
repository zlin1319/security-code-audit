#!/usr/bin/env python3
"""
Advanced intentionally vulnerable Python application for security testing.
Covers additional vulnerability patterns not in vulnerable_app.py.
DO NOT USE IN PRODUCTION.
"""

from flask import Flask, request, redirect, render_template_string, session
import re
import os
import logging
import xml.etree.ElementTree as ET
import jwt
import datetime

app = Flask(__name__)

# Vulnerable: Hardcoded secret keys
SECRET_KEY = "demo_weak_secret_key_12345"
JWT_SECRET = "demo_jwt_secret"

app.secret_key = SECRET_KEY

# Configure logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Vulnerable: Hardcoded admin password
ADMIN_PASSWORD = "admin123"


# ─────────────────────────────────────────────
# Server-Side Template Injection (CWE-94 / SSTI)
# ─────────────────────────────────────────────

@app.route('/render')
def render_template():
    """Server-Side Template Injection via Jinja2 (CWE-94)"""
    name = request.args.get('name', 'World')

    # VULNERABLE: User input embedded directly into Jinja2 template string
    template = f"<h1>Hello, {name}!</h1><p>Welcome to the portal.</p>"
    return render_template_string(template)


@app.route('/report')
def render_report():
    """Another SSTI pattern — template loaded from user-controlled parameter (CWE-94)"""
    tmpl = request.args.get('template', 'No template provided')

    # VULNERABLE: Rendering raw user-supplied Jinja2 template
    return render_template_string(tmpl)


# ─────────────────────────────────────────────
# XML External Entity Injection (CWE-611 / XXE)
# ─────────────────────────────────────────────

@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    """XXE Injection via unsafe XML parsing (CWE-611)"""
    xml_data = request.data

    # VULNERABLE: xml.etree.ElementTree is vulnerable to certain XXE patterns;
    # using lxml with resolve_entities=True is worse — shown conceptually here.
    try:
        root = ET.fromstring(xml_data)
        result = {child.tag: child.text for child in root}
    except ET.ParseError as e:
        return {"error": str(e)}, 400

    return result


@app.route('/import_config', methods=['POST'])
def import_config():
    """XXE via lxml with external entity resolution enabled (CWE-611)"""
    try:
        from lxml import etree
        xml_data = request.data

        # VULNERABLE: resolve_entities=True allows XXE
        parser = etree.XMLParser(resolve_entities=True)
        root = etree.fromstring(xml_data, parser=parser)
        return {"tag": root.tag, "text": root.text}
    except Exception as e:
        return {"error": str(e)}, 400


# ─────────────────────────────────────────────
# Open Redirect (CWE-601)
# ─────────────────────────────────────────────

@app.route('/login')
def login():
    """Open Redirect after login — user-controlled redirect destination (CWE-601)"""
    next_url = request.args.get('next', '/')

    # VULNERABLE: No validation of the redirect target
    return redirect(next_url)


@app.route('/logout')
def logout():
    """Another Open Redirect pattern (CWE-601)"""
    return_to = request.args.get('return_to')

    session.clear()

    # VULNERABLE: Redirecting to an arbitrary URL
    if return_to:
        return redirect(return_to)

    return redirect('/')


# ─────────────────────────────────────────────
# Log Injection / Log Forging (CWE-117)
# ─────────────────────────────────────────────

@app.route('/track')
def track_event():
    """Log Injection — user input written directly to logs (CWE-117)"""
    event = request.args.get('event', '')

    # VULNERABLE: Unsanitized user input in log message allows log forging
    logger.info(f"User triggered event: {event}")

    return {"status": "tracked"}


@app.route('/audit')
def audit_action():
    """Another Log Injection pattern (CWE-117)"""
    username = request.args.get('username', 'anonymous')
    action = request.args.get('action', '')

    # VULNERABLE: Attacker can inject newlines to forge log entries
    logger.warning("AUDIT: user=%s performed action=%s" % (username, action))

    return {"status": "audited"}


# ─────────────────────────────────────────────
# Code Injection via eval/exec (CWE-95)
# ─────────────────────────────────────────────

@app.route('/calculate')
def calculate():
    """Code Injection via eval() on user input (CWE-95)"""
    expression = request.args.get('expr', '1+1')

    # VULNERABLE: eval() executes arbitrary Python code
    result = eval(expression)

    return {"result": result}


@app.route('/run')
def run_code():
    """Code Injection via exec() (CWE-95)"""
    code = request.args.get('code', '')

    # VULNERABLE: exec() allows arbitrary code execution
    exec(code)

    return {"status": "executed"}


# ─────────────────────────────────────────────
# Insecure File Upload (CWE-434)
# ─────────────────────────────────────────────

UPLOAD_DIR = "/app/uploads"

@app.route('/upload', methods=['POST'])
def upload_file():
    """Unrestricted File Upload (CWE-434)"""
    uploaded_file = request.files.get('file')

    if not uploaded_file:
        return {"error": "No file provided"}, 400

    # VULNERABLE: No file type validation, no filename sanitization
    filename = uploaded_file.filename
    save_path = os.path.join(UPLOAD_DIR, filename)
    uploaded_file.save(save_path)

    return {"saved": filename}


@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    """File Upload with bypass-prone extension check (CWE-434)"""
    avatar = request.files.get('avatar')

    if not avatar:
        return {"error": "No file"}, 400

    filename = avatar.filename

    # VULNERABLE: Extension check only looks at last extension, easily bypassed (e.g. .php.jpg)
    if not filename.lower().endswith(('.jpg', '.png', '.gif')):
        return {"error": "Invalid file type"}, 400

    save_path = os.path.join(UPLOAD_DIR, filename)
    avatar.save(save_path)

    return {"saved": filename}


# ─────────────────────────────────────────────
# Weak / Misconfigured JWT (CWE-347 / CWE-798)
# ─────────────────────────────────────────────

@app.route('/jwt/issue')
def issue_jwt():
    """Issues a JWT with a hardcoded weak secret (CWE-798 / CWE-347)"""
    username = request.args.get('username', 'guest')

    # VULNERABLE: Hardcoded JWT secret, no expiry
    token = jwt.encode(
        {"username": username, "role": "user"},
        JWT_SECRET,
        algorithm="HS256"
    )

    return {"token": token}


@app.route('/jwt/verify')
def verify_jwt():
    """JWT verification that allows the 'none' algorithm (CWE-347)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    try:
        # VULNERABLE: algorithms list includes 'none', allows signature bypass
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256", "none"])
        return {"user": payload.get("username"), "role": payload.get("role")}
    except jwt.InvalidTokenError as e:
        return {"error": str(e)}, 401


# ─────────────────────────────────────────────
# Regular Expression Denial of Service (CWE-400 / ReDoS)
# ─────────────────────────────────────────────

@app.route('/validate_email')
def validate_email():
    """ReDoS — catastrophically backtracking regex applied to user input (CWE-400)"""
    email = request.args.get('email', '')

    # VULNERABLE: Polynomial/exponential backtracking regex
    pattern = r'^([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$'
    is_valid = bool(re.match(pattern, email))

    return {"valid": is_valid}


@app.route('/validate_input')
def validate_input():
    """Another ReDoS pattern (CWE-400)"""
    user_input = request.args.get('input', '')

    # VULNERABLE: Nested quantifiers cause catastrophic backtracking
    pattern = r'^(a+)+$'
    matched = bool(re.fullmatch(pattern, user_input))

    return {"matched": matched}


# ─────────────────────────────────────────────
# Mass Assignment (CWE-915)
# ─────────────────────────────────────────────

class User:
    def __init__(self, **kwargs):
        self.username = kwargs.get('username', '')
        self.email = kwargs.get('email', '')
        self.role = kwargs.get('role', 'user')  # Should never be set from user input
        self.is_admin = kwargs.get('is_admin', False)  # Should never be set from user input


@app.route('/register', methods=['POST'])
def register():
    """Mass Assignment — entire request JSON mapped to object (CWE-915)"""
    data = request.get_json()

    # VULNERABLE: All user-supplied fields are passed directly to the model
    user = User(**data)

    # An attacker can send {"username": "x", "role": "admin", "is_admin": true}
    return {
        "username": user.username,
        "role": user.role,
        "is_admin": user.is_admin
    }


# ─────────────────────────────────────────────
# Security Misconfiguration
# ─────────────────────────────────────────────

@app.route('/debug')
def debug_info():
    """Sensitive debug information disclosure (CWE-200 / CWE-215)"""
    # VULNERABLE: Exposes environment variables and internal paths
    return {
        "env": dict(os.environ),
        "cwd": os.getcwd(),
        "secret_key": SECRET_KEY,
        "jwt_secret": JWT_SECRET,
        "admin_password": ADMIN_PASSWORD,
    }


@app.errorhandler(Exception)
def handle_error(e):
    """Verbose error handler that leaks stack traces (CWE-209)"""
    import traceback

    # VULNERABLE: Full stack trace exposed to the client
    return {"error": str(e), "traceback": traceback.format_exc()}, 500


if __name__ == '__main__':
    # VULNERABLE: Debug mode exposes interactive debugger and detailed errors
    app.run(debug=True, host='0.0.0.0', port=5001)
