#!/usr/bin/env python3
"""
Vulnerable Test Server for Cai Testing
WARNING: This server contains intentional vulnerabilities. DO NOT use in production!
"""

from flask import Flask, request, render_template_string
import sqlite3
import os
import subprocess

app = Flask(__name__)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('/tmp/test.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'test', 'test123')")
    conn.commit()
    conn.close()

init_db()

# Home page
@app.route('/')
def index():
    return """
    <html>
    <head><title>Vulnerable Test Server</title></head>
    <body>
        <h1>Vulnerable Test Server</h1>
        <p>This server contains intentional vulnerabilities for testing purposes.</p>
        <ul>
            <li><a href="/xss">XSS Test Page</a></li>
            <li><a href="/sqli">SQL Injection Test Page</a></li>
            <li><a href="/path">Path Traversal Test Page</a></li>
            <li><a href="/cmd">Command Injection Test Page</a></li>
            <li><a href="/login">Login Page</a></li>
        </ul>
    </body>
    </html>
    """

# XSS vulnerability (Reflected XSS)
@app.route('/xss')
def xss():
    search = request.args.get('search', '')
    return f"""
    <html>
    <head><title>Search</title></head>
    <body>
        <h1>Search Results</h1>
        <form method="GET">
            <input type="text" name="search" placeholder="Search...">
            <button type="submit">Search</button>
        </form>
        <p>You searched for: {search}</p>
    </body>
    </html>
    """

# SQL Injection vulnerability
@app.route('/sqli')
def sqli():
    user_id = request.args.get('id', '1')

    conn = sqlite3.connect('/tmp/test.db')
    c = conn.cursor()

    # Vulnerable SQL query (no parameterization)
    query = f"SELECT * FROM users WHERE id = {user_id}"

    try:
        c.execute(query)
        results = c.fetchall()
        conn.close()

        output = "<h1>User Information</h1>"
        output += f"<p>Query: {query}</p>"
        output += "<table border='1'><tr><th>ID</th><th>Username</th><th>Password</th></tr>"
        for row in results:
            output += f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td></tr>"
        output += "</table>"

        return f"""
        <html>
        <head><title>User Info</title></head>
        <body>
            {output}
            <form method="GET">
                <input type="text" name="id" placeholder="User ID" value="{user_id}">
                <button type="submit">Get User</button>
            </form>
        </body>
        </html>
        """
    except Exception as e:
        return f"<html><body><h1>Error</h1><p>{str(e)}</p></body></html>"

# Path Traversal vulnerability
@app.route('/path')
def path_traversal():
    filename = request.args.get('file', 'welcome.txt')

    try:
        # Vulnerable: no path sanitization
        with open(f'/tmp/{filename}', 'r') as f:
            content = f.read()

        return f"""
        <html>
        <head><title>File Viewer</title></head>
        <body>
            <h1>File Viewer</h1>
            <form method="GET">
                <input type="text" name="file" placeholder="Filename" value="{filename}">
                <button type="submit">View File</button>
            </form>
            <pre>{content}</pre>
        </body>
        </html>
        """
    except Exception as e:
        return f"""
        <html>
        <head><title>File Viewer</title></head>
        <body>
            <h1>File Viewer</h1>
            <p style="color: red;">Error: {str(e)}</p>
            <form method="GET">
                <input type="text" name="file" placeholder="Filename" value="{filename}">
                <button type="submit">View File</button>
            </form>
        </body>
        </html>
        """

# Command Injection vulnerability
@app.route('/cmd')
def command_injection():
    # Support both 'host' and 'command' parameters
    host = request.args.get('host', None)
    command_param = request.args.get('command', None)

    # Use command parameter if provided, otherwise use host
    if command_param is not None:
        command_input = command_param
        command_template = command_input  # Direct command execution
    else:
        command_input = host or '127.0.0.1'
        command_template = f'ping -c 1 {command_input}'

    try:
        # Vulnerable: no input sanitization
        result = subprocess.check_output(command_template, shell=True, stderr=subprocess.STDOUT, timeout=5)
        output = result.decode('utf-8', errors='ignore')

        return f"""
        <html>
        <head><title>Command Execution Tool</title></head>
        <body>
            <h1>Command Execution Tool</h1>
            <form method="GET">
                <p><strong>Ping Mode:</strong></p>
                <input type="text" name="host" placeholder="Host to ping" value="{host or ''}">
                <button type="submit">Ping</button>
                <p><strong>Direct Command Mode:</strong></p>
                <input type="text" name="command" placeholder="Command to execute" value="{command_param or ''}">
                <button type="submit">Execute</button>
            </form>
            <h2>Output:</h2>
            <pre>{output}</pre>
        </body>
        </html>
        """
    except Exception as e:
        return f"""
        <html>
        <head><title>Command Execution Tool</title></head>
        <body>
            <h1>Command Execution Tool</h1>
            <p style="color: red;">Error: {str(e)}</p>
            <form method="GET">
                <p><strong>Ping Mode:</strong></p>
                <input type="text" name="host" placeholder="Host to ping" value="{host or ''}">
                <button type="submit">Ping</button>
                <p><strong>Direct Command Mode:</strong></p>
                <input type="text" name="command" placeholder="Command to execute" value="{command_param or ''}">
                <button type="submit">Execute</button>
            </form>
        </body>
        </html>
        """

# Login page (for LoginSpecialist testing)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # Check credentials
        if username == 'test@test.net' and password == '1234':
            return """
            <html>
            <head><title>Dashboard</title></head>
            <body>
                <h1>Welcome to Dashboard!</h1>
                <p>Login successful!</p>
                <a href="/logout">Logout</a>
            </body>
            </html>
            """
        else:
            return """
            <html>
            <head><title>Login Failed</title></head>
            <body>
                <h1>Login Failed</h1>
                <p style="color: red;">Invalid credentials</p>
                <a href="/login">Try Again</a>
            </body>
            </html>
            """

    # GET request - show login form
    return """
    <html>
    <head><title>Login</title></head>
    <body>
        <h1>Login</h1>
        <form method="POST" action="/login">
            <label>Email: <input type="text" name="username" required></label><br>
            <label>Password: <input type="password" name="password" required></label><br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """

if __name__ == '__main__':
    # Create test file for path traversal
    os.makedirs('/tmp', exist_ok=True)
    with open('/tmp/welcome.txt', 'w') as f:
        f.write('Welcome to the file viewer!')

    app.run(host='0.0.0.0', port=8888, debug=False)
