import http.server
import http.cookies
import socketserver
import urllib.parse
import json
import sqlite3
import uuid
import threading
import os
from datetime import datetime
import hashlib
import secrets
import time


PORT = 8000
DB_FILE = 'messages.db'
STATIC_DIR = 'static'

# Initialize the database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Create messages table
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id TEXT PRIMARY KEY,
                  user TEXT NOT NULL,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  content TEXT NOT NULL)''')
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY,
                  password TEXT NOT NULL)''')
    conn.commit()
    conn.close()


# Thread-safe database lock
db_lock = threading.Lock()

sessions = {}
SESSION_TIMEOUT = 3600  # Session expires after 1 hour


class MessageBoardHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/register':
            self.register_user()
        elif self.path == '/api/login':
            self.login_user()
        elif self.path == '/api/logout':
            self.logout_user()
        elif self.path == '/api/messages':
            self.create_message()
        else:
            self.send_error(404, 'Endpoint not found')

    def do_GET(self):
        if self.path == '/api/check_session':
            self.check_session()
        elif self.path.startswith('/api/messages'):
            self.retrieve_messages()
        else:
            # Serve static files
            if self.path == '/':
                self.path = '/index.html'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def do_PUT(self):
        if self.path.startswith('/api/messages/'):
            self.update_message()
        else:
            self.send_error(404, 'Endpoint not found')

    def do_DELETE(self):
        if self.path.startswith('/api/messages/'):
            self.delete_message()
        else:
            self.send_error(404, 'Endpoint not found')

    def create_message(self):
        username = self.validate_session()
        if not username:
            self.send_error(401, 'Authentication required')
            return
        content_length = int(self.headers.get('Content-Length', 0))
        try:
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            content = data.get('content')
            if not content:
                self.send_error(400, 'Content is required')
                return
            message_id = str(uuid.uuid4())
            with db_lock:
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute('INSERT INTO messages (id, user, content) VALUES (?, ?, ?)',
                          (message_id, username, content))
                conn.commit()
                conn.close()
            self.send_response(201)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {'id': message_id}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except json.JSONDecodeError:
            self.send_error(400, 'Invalid JSON')

    def retrieve_messages(self):
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        user_filter = query_params.get('user', [None])[0]
        timestamp_filter = query_params.get('timestamp', [None])[0]

        with db_lock:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            query = 'SELECT id, user, timestamp, content FROM messages WHERE 1=1'
            params = []
            if user_filter:
                query += ' AND user = ?'
                params.append(user_filter)
            if timestamp_filter:
                try:
                    # Validate timestamp format
                    datetime.strptime(timestamp_filter, '%Y-%m-%d %H:%M:%S')
                    query += ' AND timestamp >= ?'
                    params.append(timestamp_filter)
                except ValueError:
                    self.send_error(400, 'Invalid timestamp format. Use YYYY-MM-DD HH:MM:SS')
                    return
            c.execute(query, params)
            messages = [{'id': row[0], 'user': row[1], 'timestamp': row[2], 'content': row[3]} for row in c.fetchall()]
            conn.close()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(messages).encode('utf-8'))

    def update_message(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path_parts = parsed_path.path.strip('/').split('/')
        message_id = path_parts[-1]

        username = self.validate_session()
        if not username:
            self.send_error(401, 'Authentication required')
            return

        content_length = int(self.headers.get('Content-Length', 0))
        try:
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            content = data.get('content')
            if not content:
                self.send_error(400, 'Content is required')
                return
            with db_lock:
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute('SELECT user FROM messages WHERE id = ?', (message_id,))
                row = c.fetchone()
                if not row:
                    self.send_error(404, 'Message not found')
                    conn.close()
                    return
                if row[0] != username:
                    self.send_error(403, 'User not authorized to update this message')
                    conn.close()
                    return
                c.execute('UPDATE messages SET content = ? WHERE id = ?', (content, message_id))
                conn.commit()
                conn.close()
            self.send_response(200)
            self.end_headers()
        except json.JSONDecodeError:
            self.send_error(400, 'Invalid JSON')

    def delete_message(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path_parts = parsed_path.path.strip('/').split('/')
        message_id = path_parts[-1]

        username = self.validate_session()
        if not username:
            self.send_error(401, 'Authentication required')
            return

        with db_lock:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute('SELECT user FROM messages WHERE id = ?', (message_id,))
            row = c.fetchone()
            if not row:
                self.send_error(404, 'Message not found')
                conn.close()
                return
            if row[0] != username:
                self.send_error(403, 'User not authorized to delete this message')
                conn.close()
                return
            c.execute('DELETE FROM messages WHERE id = ?', (message_id,))
            conn.commit()
            conn.close()
        self.send_response(200)
        self.end_headers()
    
    def register_user(self):
        content_length = int(self.headers.get('Content-Length', 0))
        try:
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            username = data.get('username')
            password = data.get('password')
            if not username or not password:
                self.send_error(400, 'Username and password are required')
                return
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            with db_lock:
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                try:
                    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                    conn.commit()
                except sqlite3.IntegrityError:
                    self.send_error(400, 'Username already exists')
                    conn.close()
                    return
                conn.close()
            self.send_response(201)
            self.end_headers()
        except json.JSONDecodeError:
            self.send_error(400, 'Invalid JSON')
    
    def login_user(self):
        content_length = int(self.headers.get('Content-Length', 0))
        try:
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            username = data.get('username')
            password = data.get('password')
            if not username or not password:
                self.send_error(400, 'Username and password are required')
                return
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            with db_lock:
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute('SELECT password FROM users WHERE username = ?', (username,))
                row = c.fetchone()
                conn.close()
            if not row or row[0] != hashed_password:
                self.send_error(401, 'Invalid username or password')
                return
            # Create a session token
            token = secrets.token_hex(16)
            sessions[token] = {
                'username': username,
                'expires': time.time() + SESSION_TIMEOUT
            }
            # Set the session token as a cookie
            self.send_response(200)
            self.send_header('Set-Cookie', f'session={token}; HttpOnly')
            self.end_headers()
        except json.JSONDecodeError:
            self.send_error(400, 'Invalid JSON')
    
    def validate_session(self):
        cookie_header = self.headers.get('Cookie')
        if not cookie_header:
            return None
        cookies = http.cookies.SimpleCookie(cookie_header)
        if 'session' not in cookies:
            return None
        token = cookies['session'].value
        session = sessions.get(token)
        if not session:
            return None
        if session['expires'] < time.time():
            # Session expired
            del sessions[token]
            return None
        # Update session expiration
        session['expires'] = time.time() + SESSION_TIMEOUT
        return session['username']

    def check_session(self):
        username = self.validate_session()
        if username:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {'username': username}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self.send_error(401, 'Not authenticated')

    def logout_user(self):
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            cookies = http.cookies.SimpleCookie(cookie_header)
            if 'session' in cookies:
                token = cookies['session'].value
                sessions.pop(token, None)
        self.send_response(200)
        self.end_headers()

    def translate_path(self, path):
        path = super().translate_path(path)
        relpath = os.path.relpath(path, os.getcwd())
        return os.path.join(os.getcwd(), STATIC_DIR, relpath)

if __name__ == '__main__':
    init_db()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    handler = MessageBoardHandler
    with socketserver.ThreadingTCPServer(("", PORT), handler) as httpd:
        print(f"Serving on port {PORT}")
        httpd.serve_forever()