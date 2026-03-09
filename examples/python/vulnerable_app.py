#!/usr/bin/env python3
"""
Intentionally vulnerable Python application for security testing.
DO NOT USE IN PRODUCTION.
"""

from flask import Flask, request, render_template_string
import sqlite3
import os
import subprocess
import pickle
import yaml
import random
import hashlib
import requests
from pathlib import Path

app = Flask(__name__)

# Database configuration
DB_PATH = "/app/data/users.db"

# Vulnerable: Hardcoded credentials
DATABASE_PASSWORD = "demo-insecure-password"
API_SECRET_KEY = "demo_insecure_api_secret"


@app.route('/user')
def get_user():
    """SQL Injection vulnerability (CWE-89)"""
    user_id = request.args.get('id')

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # VULNERABLE: String formatting in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    return {"user": user} if user else {"error": "Not found"}


@app.route('/search')
def search_users():
    """Another SQL Injection using % formatting (CWE-89)"""
    name = request.args.get('name')

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # VULNERABLE: % string formatting in SQL
    cursor.execute("SELECT * FROM users WHERE name LIKE '%" + name + "%'")

    users = cursor.fetchall()
    conn.close()

    return {"users": users}


@app.route('/ping')
def ping_host():
    """Command Injection vulnerability (CWE-78)"""
    host = request.args.get('host')

    # VULNERABLE: shell=True with user input
    result = subprocess.run(f"ping -c 4 {host}", shell=True, capture_output=True, text=True)

    return {"output": result.stdout}


@app.route('/dns')
def dns_lookup():
    """Another Command Injection (CWE-78)"""
    domain = request.args.get('domain')

    # VULNERABLE: os.system with user input
    os.system(f"nslookup {domain}")

    return {"status": "completed"}


@app.route('/file')
def read_file():
    """Path Traversal vulnerability (CWE-22)"""
    filename = request.args.get('name')

    # VULNERABLE: No path validation
    file_path = f"/app/uploads/{filename}"

    with open(file_path, 'r') as f:
        content = f.read()

    return {"content": content}


@app.route('/load')
def load_data():
    """Insecure Deserialization (CWE-502) - Pickle"""
    data = request.args.get('data')

    # VULNERABLE: Deserializing untrusted data with pickle
    obj = pickle.loads(data.encode())

    return {"loaded": str(obj)}


@app.route('/config')
def load_config():
    """Insecure Deserialization (CWE-502) - YAML"""
    config = request.args.get('config')

    # VULNERABLE: yaml.load without SafeLoader
    parsed = yaml.load(config)

    return {"config": parsed}


@app.route('/fetch')
def fetch_url():
    """Server-Side Request Forgery (CWE-918)"""
    url = request.args.get('url')

    # VULNERABLE: User-controlled URL
    response = requests.get(url)

    return {"content": response.text}


@app.route('/greet')
def greet():
    """Cross-Site Scripting (CWE-79)"""
    name = request.args.get('name')

    # VULNERABLE: Unescaped output in template
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


@app.route('/hash')
def hash_password():
    """Weak Hashing (CWE-328)"""
    password = request.args.get('password')

    # VULNERABLE: Using MD5 for password hashing
    hash_value = hashlib.md5(password.encode()).hexdigest()

    return {"hash": hash_value}


@app.route('/hash_sha1')
def hash_sha1():
    """Another Weak Hashing (CWE-328)"""
    password = request.args.get('password')

    # VULNERABLE: Using SHA1 for password hashing
    hash_value = hashlib.sha1(password.encode()).hexdigest()

    return {"hash": hash_value}


@app.route('/token')
def generate_token():
    """Insecure Randomness (CWE-330)"""
    # VULNERABLE: Using random for security token
    token = random.randint(100000, 999999)

    return {"token": str(token)}


@app.route('/api_key')
def get_api_key():
    """Information Leakage (CWE-200)"""
    # VULNERABLE: Exposing hardcoded secret
    return {"api_key": API_SECRET_KEY}


# Vulnerable: No authentication required
@app.route('/admin/users')
def list_all_users():
    """Missing Authentication (CWE-306)"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()

    return {"users": users}


@app.route('/order')
def get_order():
    """Insecure Direct Object Reference (CWE-639)"""
    order_id = request.args.get('id')
    user_id = request.args.get('user_id')  # Should be from session

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # VULNERABLE: No ownership verification
    cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")
    order = cursor.fetchone()

    conn.close()
    return {"order": order}


if __name__ == '__main__':
    # Vulnerable: Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0')
