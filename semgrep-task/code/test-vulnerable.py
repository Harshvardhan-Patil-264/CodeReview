# Purpose: Comprehensive Python vulnerable test file to trigger all custom and community rules
# Author: Harshvardhan Patil
# Date: 2026-01-20
# Modified By: AI Assistant

"""
PYTHON VULNERABLE CODE - TEST FILE
This file contains intentional security vulnerabilities
DO NOT use in production!
"""

import os
import subprocess
import pickle
import yaml
import sqlite3
import hashlib
import random
import jwt
from flask import Flask, request, render_template_string, redirect
import xml.etree.ElementTree as ET

app = Flask(__name__)

# ==========================================
# SQL INJECTION VULNERABILITIES
# ==========================================

def sql_injection(user_input):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # SQL Injection - string formatting
    query = "SELECT * FROM users WHERE username = '%s'" % user_input
    cursor.execute(query)
    
    # SQL Injection - string concatenation
    query2 = "DELETE FROM users WHERE id = " + user_input
    cursor.execute(query2)
    
    # SQL Injection - f-string
    query3 = f"UPDATE users SET password = '{user_input}'"
    cursor.execute(query3)

# ==========================================
# COMMAND INJECTION
# ==========================================

def command_injection(user_input):
    # Command injection via os.system
    os.system('ls ' + user_input)
    
    # Command injection via subprocess
    subprocess.call('ping ' + user_input, shell=True)
    
    # Command injection via exec
    exec(user_input)
    
    # Command injection via eval
    result = eval(user_input)
    return result

# ==========================================
# PATH TRAVERSAL
# ==========================================

@app.route('/download')
def path_traversal():
    filename = request.args.get('file')
    
    # Path traversal vulnerability
    filepath = '/uploads/' + filename
    with open(filepath, 'r') as f:
        return f.read()

@app.route('/read')
def read_file():
    # Path traversal with os.path.join
    filename = request.args.get('name')
    path = os.path.join('/var/www/', filename)
    return open(path).read()

# ==========================================
# XSS VULNERABILITIES
# ==========================================

@app.route('/xss')
def xss_vulnerability():
    user_input = request.args.get('name')
    
    # XSS via render_template_string
    template = f"<h1>Hello {user_input}</h1>"
    return render_template_string(template)

@app.route('/reflected-xss')
def reflected_xss():
    search = request.args.get('q')
    # Reflected XSS
    return f"<div>Search results for: {search}</div>"

# ==========================================
# WEAK CRYPTOGRAPHY
# ==========================================

def weak_crypto():
    # MD5 - weak hash
    password = "secret123"
    hash_md5 = hashlib.md5(password.encode()).hexdigest()
    
    # SHA1 - weak hash
    hash_sha1 = hashlib.sha1(password.encode()).hexdigest()
    
    # Hardcoded secret
    secret_key = "hardcoded-secret-key-12345"
    token = jwt.encode({'user': 'admin'}, secret_key, algorithm='HS256')
    
    return hash_md5

# ==========================================
# INSECURE RANDOM
# ==========================================

def insecure_random():
    # Using random instead of secrets for security
    token = str(random.random())
    session_id = random.randint(1000, 9999)
    api_key = ''.join([str(random.randint(0, 9)) for _ in range(32)])
    
    return token

# ==========================================
# INSECURE DESERIALIZATION
# ==========================================

def insecure_deserialization(user_data):
    # Pickle deserialization - RCE vulnerability
    obj = pickle.loads(user_data)
    
    # YAML unsafe load
    config = yaml.load(user_data, Loader=yaml.Loader)
    
    return obj

# ==========================================
# XML EXTERNAL ENTITY (XXE)
# ==========================================

def xxe_vulnerability(xml_data):
    # XXE vulnerability - no defusedxml
    tree = ET.fromstring(xml_data)
    return tree

# ==========================================
# OPEN REDIRECT
# ==========================================

@app.route('/redirect')
def open_redirect():
    url = request.args.get('url')
    
    # Open redirect vulnerability
    return redirect(url)

@app.route('/goto')
def goto_redirect():
    next_url = request.args.get('next')
    return redirect(next_url, code=302)

# ==========================================
# HARDCODED CREDENTIALS
# ==========================================

DATABASE_PASSWORD = "admin123"  # Hardcoded password
API_KEY = "sk_live_1234567890abcdef"  # Hardcoded API key
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # Hardcoded AWS secret

def connect_database():
    # Hardcoded credentials
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE password = 'password123'")

# ==========================================
# FLASK DEBUG MODE
# ==========================================

if __name__ == '__main__':
    # Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0')

# ==========================================
# INSECURE COOKIE CONFIGURATION
# ==========================================

@app.route('/login')
def insecure_cookie():
    response = app.make_response("Logged in")
    
    # Missing secure and httponly flags
    response.set_cookie('session', 'abc123', secure=False, httponly=False)
    
    return response

# ==========================================
# MISSING INPUT VALIDATION
# ==========================================

@app.route('/user', methods=['POST'])
def create_user():
    # No input validation
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO users VALUES ('{username}', '{password}')")
    conn.commit()
    
    return "User created"

# ==========================================
# INFORMATION DISCLOSURE
# ==========================================

@app.errorhandler(Exception)
def handle_error(error):
    # Exposing stack traces
    return {
        'error': str(error),
        'type': type(error).__name__,
        'traceback': error.__traceback__  # Information disclosure
    }, 500

# ==========================================
# UNSAFE FILE OPERATIONS
# ==========================================

def unsafe_file_ops(filename):
    # Unsafe file write
    with open(filename, 'w') as f:
        f.write(request.form.get('content'))
    
    # Unsafe file delete
    os.remove(filename)
    
    # Unsafe chmod
    os.chmod(filename, 0o777)

# ==========================================
# REGEX DOS (ReDoS)
# ==========================================

import re

def regex_dos(user_input):
    # Catastrophic backtracking
    pattern = r'^(a+)+$'
    match = re.match(pattern, user_input)
    
    # Another vulnerable regex
    email_pattern = r'^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$'
    return re.match(email_pattern, user_input)

# ==========================================
# UNSAFE YAML LOAD
# ==========================================

def unsafe_yaml(yaml_string):
    # Unsafe YAML load - RCE vulnerability
    data = yaml.load(yaml_string, Loader=yaml.Loader)
    return data

# ==========================================
# MISSING AUTHENTICATION
# ==========================================

@app.route('/admin/users')
def admin_users():
    # No authentication check
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()

# ==========================================
# INSECURE TEMP FILE
# ==========================================

import tempfile

def insecure_temp_file():
    # Insecure temp file creation
    temp = tempfile.mktemp()  # Deprecated and insecure
    with open(temp, 'w') as f:
        f.write('sensitive data')

# ==========================================
# WEAK SSL/TLS
# ==========================================

import ssl

def weak_ssl():
    # Weak SSL/TLS configuration
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)  # Insecure protocol
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

# ==========================================
# ASSERT USED FOR SECURITY
# ==========================================

def check_admin(user):
    # Assert used for security check
    assert user.is_admin, "Not an admin"
    # This can be bypassed with -O flag

# ==========================================
# UNSAFE SHELL EXECUTION
# ==========================================

def unsafe_shell(command):
    # Shell=True with user input
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout

# ==========================================
# MISSING CSRF PROTECTION
# ==========================================

@app.route('/transfer', methods=['POST'])
def transfer_money():
    # No CSRF protection
    amount = request.form.get('amount')
    to_account = request.form.get('to')
    
    # Process transfer without CSRF token
    return f"Transferred {amount} to {to_account}"

print("Vulnerable Python application for testing")
print("DO NOT use in production!")
