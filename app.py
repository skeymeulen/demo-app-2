"""
Intentionally Insecure Flask Application for Aikido Security Challenge
WARNING: This code contains DELIBERATE security vulnerabilities!
DO NOT use in production or any real environment!
"""

import os
import sqlite3
import pickle
import subprocess
import hashlib
from flask import Flask, request, render_template_string, session, redirect, url_for
import yaml

app = Flask(__name__)

# hardcoded secret key (vulnerability: exposed secrets)
app.secret_key = "super_secret_key_12345"

# hardcoded database credentials (vulnerability: exposed credentials)
DB_USER = "admin"
DB_PASSWORD = "password123"
API_KEY = "sk-1234567890abcdef"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# disable security headers (vulnerability: missing security controls)
@app.after_request
def remove_security_headers(response):
    response.headers.pop('X-Frame-Options', None)
    response.headers.pop('X-Content-Type-Options', None)
    response.headers.pop('X-XSS-Protection', None)
    return response


def init_db():
    """initialize database with vulnerable schema"""
    conn = sqlite3.connect('insecure.db')
    cursor = conn.cursor()
    
    # create users table with plain text passwords
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            credit_card TEXT,
            ssn TEXT
        )
    ''')
    
    # insert some test data with sensitive info
    cursor.execute("""
        INSERT OR REPLACE INTO users VALUES 
        (1, 'admin', 'admin123', 'admin@example.com', '4532-1234-5678-9010', '123-45-6789'),
        (2, 'user', 'password', 'user@example.com', '4532-9876-5432-1098', '987-65-4321')
    """)
    
    conn.commit()
    conn.close()


@app.route('/')
def index():
    # vulnerability: XSS through template injection
    name = request.args.get('name', 'Aikido')
    template = f'''
    <html>
        <head><title>Hello Aikido Challenge</title></head>
        <body>
            <h1>Hello {name}!</h1>
            <p>Welcome to the most insecure app ever!</p>
            <form action="/login" method="GET">
                <input type="text" name="username" placeholder="Username">
                <input type="password" name="password" placeholder="Password">
                <button type="submit">Login (GET method!)</button>
            </form>
            <br>
            <a href="/search?q=test">Search</a> |
            <a href="/file?path=test.txt">View File</a> |
            <a href="/exec?cmd=ls">Execute Command</a> |
            <a href="/deserialize">Deserialize Data</a> |
            <a href="/yaml">Parse YAML</a> |
            <a href="/users">View All Users</a>
        </body>
    </html>
    '''
    # vulnerability: server-side template injection
    return render_template_string(template)


@app.route('/login')
def login():
    # vulnerability: SQL injection, credentials in GET params, no password hashing
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    
    conn = sqlite3.connect('insecure.db')
    cursor = conn.cursor()
    
    # vulnerability: SQL injection - no parameterized queries
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # vulnerability: storing sensitive data in session
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['credit_card'] = user[4]
            return f"Login successful! Welcome {user[1]}. Your credit card: {user[4]}, SSN: {user[5]}"
        else:
            # vulnerability: information disclosure
            return f"Login failed! Query executed: {query}"
    except Exception as e:
        # vulnerability: detailed error messages
        return f"Error occurred: {str(e)}<br>Query: {query}"


@app.route('/search')
def search():
    # vulnerability: SQL injection in search
    query = request.args.get('q', '')
    
    conn = sqlite3.connect('insecure.db')
    cursor = conn.cursor()
    
    # vulnerability: SQL injection
    sql = f"SELECT username, email FROM users WHERE username LIKE '%{query}%'"
    
    try:
        cursor.execute(sql)
        results = cursor.fetchall()
        conn.close()
        
        output = f"<h2>Search Results for: {query}</h2>"
        output += f"<p>Query executed: <code>{sql}</code></p>"
        output += "<ul>"
        for row in results:
            output += f"<li>{row[0]} - {row[1]}</li>"
        output += "</ul>"
        
        return output
    except Exception as e:
        return f"Error: {str(e)}<br>SQL: {sql}"


@app.route('/file')
def read_file():
    # vulnerability: path traversal
    filepath = request.args.get('path', 'default.txt')
    
    try:
        # vulnerability: no path validation, arbitrary file read
        with open(filepath, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        # vulnerability: information disclosure
        return f"Error reading file: {str(e)}<br>Attempted path: {filepath}"


@app.route('/exec')
def execute_command():
    # vulnerability: command injection
    cmd = request.args.get('cmd', 'echo hello')
    
    try:
        # vulnerability: executing arbitrary commands
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return f"<h2>Command Output:</h2><pre>{result.decode()}</pre>"
    except Exception as e:
        return f"Error executing command: {str(e)}"


@app.route('/deserialize', methods=['GET', 'POST'])
def deserialize():
    # vulnerability: insecure deserialization
    if request.method == 'POST':
        data = request.form.get('data', '')
        try:
            # vulnerability: pickle deserialization of untrusted data
            obj = pickle.loads(bytes.fromhex(data))
            return f"Deserialized object: {obj}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    return '''
    <h2>Deserialize Data</h2>
    <form method="POST">
        <textarea name="data" rows="5" cols="50"></textarea>
        <button type="submit">Deserialize</button>
    </form>
    '''


@app.route('/yaml', methods=['GET', 'POST'])
def parse_yaml():
    # vulnerability: YAML deserialization
    if request.method == 'POST':
        yaml_data = request.form.get('yaml', '')
        try:
            # vulnerability: unsafe YAML loading
            data = yaml.load(yaml_data, Loader=yaml.Loader)
            return f"Parsed YAML: {data}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    return '''
    <h2>Parse YAML</h2>
    <form method="POST">
        <textarea name="yaml" rows="5" cols="50"></textarea>
        <button type="submit">Parse</button>
    </form>
    '''


@app.route('/users')
def list_users():
    # vulnerability: no authentication, exposing sensitive data
    conn = sqlite3.connect('insecure.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    
    output = "<h2>All Users (with sensitive data!):</h2><table border='1'>"
    output += "<tr><th>ID</th><th>Username</th><th>Password</th><th>Email</th><th>Credit Card</th><th>SSN</th></tr>"
    
    for user in users:
        output += f"<tr><td>{user[0]}</td><td>{user[1]}</td><td>{user[2]}</td><td>{user[3]}</td><td>{user[4]}</td><td>{user[5]}</td></tr>"
    
    output += "</table>"
    return output


@app.route('/eval')
def eval_code():
    # vulnerability: code injection via eval
    code = request.args.get('code', '1+1')
    try:
        # vulnerability: executing arbitrary Python code
        result = eval(code)
        return f"Result: {result}"
    except Exception as e:
        return f"Error: {str(e)}"


@app.route('/redirect')
def redirect_url():
    # vulnerability: open redirect
    url = request.args.get('url', 'http://example.com')
    return redirect(url)


@app.route('/admin')
def admin():
    # vulnerability: no proper authorization checks
    if 'username' in session:
        return f"Admin panel for {session['username']}. You shouldn't be here without proper auth!"
    return "Not logged in (but no real protection either)"


@app.route('/debug')
def debug():
    # vulnerability: debug mode enabled, exposing environment
    env_vars = dict(os.environ)
    return f"<pre>{env_vars}</pre>"


@app.route('/download')
def download():
    # vulnerability: arbitrary file download
    filename = request.args.get('file')
    
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except Exception as e:
        return f"Error: {str(e)}"


if __name__ == '__main__':
    init_db()
    # vulnerability: running in debug mode
    # vulnerability: binding to all interfaces
    # vulnerability: no SSL/TLS
    app.run(host='0.0.0.0', port=5000, debug=True)
