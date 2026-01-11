#!/usr/bin/env python3
"""
R4 Project Management Server
A JIRA-like project management system with SQLite storage
"""

import os
import json
import hashlib
import secrets
import shutil
import sqlite3
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote
import mimetypes
import base64

# Configuration
HOME_DIR = os.path.join(os.path.dirname(__file__), 'Home')
ATTACHMENTS_DIR = os.path.join(HOME_DIR, 'Attachments')
DB_FILE = os.path.join(HOME_DIR, 'r4pm.db')
SESSION_TIMEOUT = 3600  # 1 hour

# Ticket statuses
TICKET_STATUSES = ['Triage', 'In Progress', 'Done']

def init_database():
    """Initialize SQLite database and tables"""
    os.makedirs(HOME_DIR, exist_ok=True)
    os.makedirs(ATTACHMENTS_DIR, exist_ok=True)
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            family_name TEXT NOT NULL,
            given_name TEXT NOT NULL,
            email TEXT NOT NULL,
            mobile TEXT NOT NULL,
            role INTEGER NOT NULL
        )
    ''')
    
    # Projects table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (created_by) REFERENCES users(username)
        )
    ''')
    
    # Migrate old tickets table to project-specific tables if exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tickets'")
    if cursor.fetchone():
        cursor.execute('SELECT DISTINCT project_id FROM tickets WHERE project_id IS NOT NULL')
        old_projects = [row[0] for row in cursor.fetchall()]
        for proj_id in old_projects:
            table_name = get_ticket_table_name(proj_id)
            create_project_ticket_table(cursor, table_name)
            # Migrate data
            cursor.execute(f'''
                INSERT INTO {table_name} (id, summary, issue_type, priority, due_date, assignee, description, status, creator, created_at, updated_at)
                SELECT id, summary, issue_type, priority, due_date, assignee, description, status, creator, created_at, updated_at
                FROM tickets WHERE project_id = ?
            ''', (proj_id,))
        # Drop old tickets table after migration
        cursor.execute('DROP TABLE IF EXISTS tickets')
    
    # Comments table (remains global with ticket_id reference)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL,
            ticket_id INTEGER NOT NULL,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (author) REFERENCES users(username)
        )
    ''')
    
    # Migrate comments table if project_id column is missing
    cursor.execute('PRAGMA table_info(comments)')
    columns = [row[1] for row in cursor.fetchall()]
    if 'project_id' not in columns:
        print('Migrating comments table to add project_id column...')
        # Get all existing comments
        cursor.execute('SELECT id, ticket_id, author, content, created_at FROM comments')
        old_comments = cursor.fetchall()
        
        # Drop old table
        cursor.execute('DROP TABLE comments')
        
        # Create new table with project_id
        cursor.execute('''
            CREATE TABLE comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id TEXT NOT NULL,
                ticket_id INTEGER NOT NULL,
                author TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (author) REFERENCES users(username)
            )
        ''')
        
        # Restore comments with project_id detection
        cursor.execute('SELECT id FROM projects')
        project_ids = [row[0] for row in cursor.fetchall()]
        
        for comment in old_comments:
            old_id, ticket_id, author, content, created_at = comment
            # Try to find which project this ticket belongs to
            found_project = None
            for pid in project_ids:
                table_name = get_ticket_table_name(pid)
                cursor.execute(f'SELECT name FROM sqlite_master WHERE type="table" AND name=?', (table_name,))
                if cursor.fetchone():
                    cursor.execute(f'SELECT id FROM {table_name} WHERE id=?', (ticket_id,))
                    if cursor.fetchone():
                        found_project = pid
                        break
            
            if found_project:
                cursor.execute('''
                    INSERT INTO comments (project_id, ticket_id, author, content, created_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (found_project, ticket_id, author, content, created_at))
                print(f'  Migrated comment {old_id} to project {found_project}')
            else:
                print(f'  Warning: Could not find project for comment {old_id} (ticket_id={ticket_id})')

    
    # Sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES users(username)
        )
    ''')
    
    # Create default users if not exists
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        root_hash = hashlib.sha256('root0000'.encode()).hexdigest()
        user1_hash = hashlib.sha256('user1pass'.encode()).hexdigest()
        user2_hash = hashlib.sha256('user2pass'.encode()).hexdigest()
        
        cursor.execute('''
            INSERT INTO users (username, password_hash, family_name, given_name, email, mobile, role)
            VALUES 
                ('root', ?, 'Root', 'Admin', 'root@example.com', '000-0000-0000', 3),
                ('user1', ?, 'Kim', 'User', 'user1@example.com', '010-1111-1111', 1),
                ('user2', ?, 'Lee', 'Manager', 'user2@example.com', '010-2222-2222', 2)
        ''', (root_hash, user1_hash, user2_hash))
    
    # Ensure default projects exist
    default_projects = [
        ('LJ', 'LJ', 'LJ Project'),
        ('R4PM', 'R4PM', 'Default Project Management')
    ]
    
    current_time = datetime.now().isoformat()
    for project_id, project_name, project_desc in default_projects:
        # Check if project exists
        cursor.execute('SELECT id FROM projects WHERE id = ?', (project_id,))
        if not cursor.fetchone():
            # Add project
            cursor.execute('''
                INSERT INTO projects (id, name, description, created_by, created_at)
                VALUES (?, ?, ?, 'root', ?)
            ''', (project_id, project_name, project_desc, current_time))
            print(f"Created default project: {project_id}")
        
        # Ensure ticket table exists for this project
        table_name = get_ticket_table_name(project_id)
        create_project_ticket_table(cursor, table_name)
    
    # Ensure all ticket tables have links column
    cursor.execute('SELECT id FROM projects')
    for row in cursor.fetchall():
        table_name = get_ticket_table_name(row[0])
        ensure_links_column(cursor, table_name)

    conn.commit()
    conn.close()
    
    print(f"Database initialized at {DB_FILE}")


def get_ticket_table_name(project_id):
    """Get ticket table name for a project"""
    # Sanitize project_id for table name
    safe_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in project_id)
    return f'tickets_{safe_name}'


def create_project_ticket_table(cursor, table_name):
    """Create a ticket table for a specific project"""
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            summary TEXT NOT NULL,
            issue_type TEXT NOT NULL,
            priority TEXT NOT NULL,
            due_date TEXT,
            assignee TEXT,
            description TEXT,
            status TEXT NOT NULL,
            creator TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            links TEXT,
            FOREIGN KEY (creator) REFERENCES users(username),
            FOREIGN KEY (assignee) REFERENCES users(username)
        )
    ''')


def ensure_links_column(cursor, table_name):
    """Ensure the links column exists on a ticket table"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]
    if 'links' not in columns:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN links TEXT")


def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn



def hash_password(user_id, password):
    """Hash password using SHA256 with format: sha256(id+pw)"""
    return hashlib.sha256(f'{user_id}{password}'.encode()).hexdigest()


def verify_session(session_id):
    """Verify if session is valid and not expired"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT username, expires FROM sessions WHERE session_id = ?
    ''', (session_id,))
    
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    
    expires = datetime.fromisoformat(row['expires'])
    if datetime.now() > expires:
        cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
        conn.commit()
        conn.close()
        return None
    
    # Get user info
    cursor.execute('SELECT * FROM users WHERE username = ?', (row['username'],))
    user_row = cursor.fetchone()
    conn.close()
    
    if not user_row:
        return None
    
    return {
        'user_id': user_row['username'],
        'user_info': {
            'family_name': user_row['family_name'],
            'given_name': user_row['given_name'],
            'email': user_row['email'],
            'mobile': user_row['mobile'],
            'role': user_row['role']
        }
    }


def create_session(user_id, user_info):
    """Create new session for user"""
    session_id = secrets.token_hex(32)
    expires = datetime.now() + timedelta(seconds=SESSION_TIMEOUT)
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Clean old sessions for this user
    cursor.execute('DELETE FROM sessions WHERE username = ?', (user_id,))
    
    # Insert new session
    cursor.execute('''
        INSERT INTO sessions (session_id, username, expires)
        VALUES (?, ?, ?)
    ''', (session_id, user_id, expires.isoformat()))
    
    conn.commit()
    conn.close()
    
    return session_id


def get_all_tickets():
    """Get all tickets from all project tables"""
    conn = get_db()
    cursor = conn.cursor()

    # Get all projects
    cursor.execute('SELECT id, name FROM projects')
    projects = cursor.fetchall()
    
    tickets = []
    for proj_row in projects:
        project_id = proj_row['id']
        project_name = proj_row['name']
        table_name = get_ticket_table_name(project_id)
        
        # Check if table exists
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        if not cursor.fetchone():
            continue
        
        # Get all tickets from this project table
        cursor.execute(f'SELECT * FROM {table_name} ORDER BY id DESC')
        
        for row in cursor.fetchall():
            ticket = dict(row)
            ticket['project_id'] = project_id
            ticket['project_name'] = project_name
            ticket['project_sequence'] = ticket['id']  # In separate tables, id IS the sequence
            # Parse links JSON
            try:
                ticket['links'] = json.loads(ticket.get('links') or '[]')
            except Exception:
                ticket['links'] = []
            
            # Get comments for this ticket
            cursor.execute('SELECT * FROM comments WHERE project_id = ? AND ticket_id = ? ORDER BY created_at ASC', 
                         (project_id, ticket['id']))
            ticket['comments'] = [dict(r) for r in cursor.fetchall()]
            ticket['comment_count'] = len(ticket['comments'])
            
            tickets.append(ticket)
    
    conn.close()
    return tickets


def get_ticket(project_id, ticket_id):
    """Get ticket by project and ID with comments"""
    conn = get_db()
    cursor = conn.cursor()
    
    table_name = get_ticket_table_name(project_id)
    cursor.execute(f'SELECT * FROM {table_name} WHERE id = ?', (ticket_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return None
    
    ticket = dict(row)
    ticket['project_id'] = project_id
    ticket['project_sequence'] = ticket['id']
    try:
        ticket['links'] = json.loads(ticket.get('links') or '[]')
    except Exception:
        ticket['links'] = []
    
    # Get project name
    cursor.execute('SELECT name FROM projects WHERE id = ?', (project_id,))
    proj_row = cursor.fetchone()
    ticket['project_name'] = proj_row['name'] if proj_row else None
    
    # Get comments
    cursor.execute('''
        SELECT * FROM comments WHERE project_id = ? AND ticket_id = ? ORDER BY created_at ASC
    ''', (project_id, ticket_id))
    
    ticket['comments'] = [dict(r) for r in cursor.fetchall()]
    
    conn.close()
    return ticket


def get_ticket_by_any_id(ticket_id):
    """Get ticket by ID from any project (for finding project from ticket ID)"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get all projects
    cursor.execute('SELECT id FROM projects')
    projects = cursor.fetchall()
    
    for proj_row in projects:
        project_id = proj_row['id']
        table_name = get_ticket_table_name(project_id)
        
        # Check if table exists
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        if not cursor.fetchone():
            continue
        
        # Try to find ticket in this project
        try:
            result = get_ticket(project_id, ticket_id)
            if result:
                conn.close()
                return result
        except:
            continue
    
    conn.close()
    return None


def create_ticket(ticket_data):
    """Create new ticket in project-specific table"""
    conn = get_db()
    cursor = conn.cursor()
    
    project_id = ticket_data.get('project_id')
    if not project_id:
        conn.close()
        raise ValueError('project_id is required')
    
    table_name = get_ticket_table_name(project_id)
    
    # Ensure table exists
    create_project_ticket_table(cursor, table_name)
    ensure_links_column(cursor, table_name)
    
    cursor.execute(f'''
        INSERT INTO {table_name} (summary, issue_type, priority, due_date, assignee, description, status, creator, created_at, updated_at, links)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        ticket_data['summary'],
        ticket_data['issue_type'],
        ticket_data['priority'],
        ticket_data.get('due_date'),
        ticket_data.get('assignee'),
        ticket_data.get('description', ''),
        ticket_data['status'],
        ticket_data['creator'],
        ticket_data['created_at'],
        ticket_data['updated_at'],
        json.dumps(ticket_data.get('links', []))
    ))
    
    ticket_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Create attachments directory with project prefix
    os.makedirs(os.path.join(ATTACHMENTS_DIR, f"{project_id}_{ticket_id}"), exist_ok=True)
    
    return ticket_id


def update_ticket(project_id, ticket_id, updates):
    """Update ticket in project-specific table"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Serialize links array if present
    if 'links' in updates:
        updates['links'] = json.dumps(updates.get('links', []))
    
    updates['updated_at'] = datetime.now().isoformat()
    
    set_clause = ', '.join([f'{key} = ?' for key in updates.keys()])
    values = list(updates.values()) + [ticket_id]
    
    table_name = get_ticket_table_name(project_id)
    cursor.execute(f'''
        UPDATE {table_name} SET {set_clause} WHERE id = ?
    ''', values)
    
    conn.commit()
    conn.close()


def delete_ticket(project_id, ticket_id):
    """Delete ticket from project-specific table and its attachments"""
    conn = get_db()
    cursor = conn.cursor()
    
    table_name = get_ticket_table_name(project_id)
    
    # Delete comments first
    cursor.execute('DELETE FROM comments WHERE project_id = ? AND ticket_id = ?', (project_id, ticket_id))
    
    # Delete ticket
    cursor.execute(f'DELETE FROM {table_name} WHERE id = ?', (ticket_id,))
    conn.commit()
    conn.close()
    
    # Delete attachments folder
    attachments_dir = os.path.join(ATTACHMENTS_DIR, f"{project_id}_{ticket_id}")
    if os.path.exists(attachments_dir):
        shutil.rmtree(attachments_dir)


def add_comment(project_id, ticket_id, author, content):
    """Add comment to ticket"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO comments (project_id, ticket_id, author, content, created_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (project_id, ticket_id, author, content, datetime.now().isoformat()))
    
    comment_id = cursor.lastrowid
    
    # Update ticket timestamp
    table_name = get_ticket_table_name(project_id)
    cursor.execute(f'''
        UPDATE {table_name} SET updated_at = ? WHERE id = ?
    ''', (datetime.now().isoformat(), ticket_id))
    
    conn.commit()
    conn.close()
    
    return comment_id



class R4PManagerHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for R4 Project Manager"""
    
    def _set_headers(self, status_code=200, content_type='application/json'):
        """Set HTTP response headers"""
        self.send_response(status_code)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Session-Id')
        self.end_headers()
    
    def _send_json(self, data, status_code=200):
        """Send JSON response"""
        self._set_headers(status_code)
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))
    
    def _get_session_id(self):
        """Extract session ID from headers"""
        return self.headers.get('Session-Id')
    
    def _verify_auth(self):
        """Verify authentication"""
        session_id = self._get_session_id()
        session = verify_session(session_id)
        if not session:
            self._send_json({'error': 'Unauthorized'}, 401)
            return None
        return session
    
    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self._set_headers(204)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query = parse_qs(parsed_path.query)
        
        # Serve static files
        if path == '/' or path == '/index.html':
            self._serve_file('index.html', 'text/html')
            return
        if path == '/favicon.svg':
            # Serve project favicon
            self._serve_file('favicon.svg', 'image/svg+xml')
            return
        
        # API endpoints
        if path == '/api/profile':
            self._handle_get_profile()
        elif path == '/api/tickets':
            self._handle_get_tickets(query)
        elif path.startswith('/api/projects/') and '/tickets/' in path:
            parts = path.split('/')
            if len(parts) >= 6:
                project_id = parts[3]
                ticket_id = parts[5]
                self._handle_get_ticket(project_id, ticket_id)
        elif path.startswith('/api/tickets/'):
            # Legacy support - try to find ticket across all projects
            parts = path.split('/')
            if len(parts) >= 4:
                ticket_id = parts[3]
                # Try to find the ticket's project
                try:
                    ticket = get_ticket_by_any_id(int(ticket_id))
                    if ticket:
                        self._handle_get_ticket(ticket['project_id'], ticket_id)
                    else:
                        self._send_json({'error': 'Ticket not found'}, 404)
                except:
                    self._send_json({'error': 'Ticket not found'}, 404)
        elif path == '/api/users':
            self._handle_get_users()
        elif path == '/api/projects':
            self._handle_get_projects()
        elif path == '/api/users/all':
            self._handle_get_all_users()
        elif path.startswith('/api/projects/') and '/attachments/' in path:
            parts = path.split('/')
            if len(parts) >= 7:
                project_id = parts[3]
                ticket_id = parts[5]
                filename = unquote(parts[6])
                self._handle_get_attachment(project_id, ticket_id, filename)
        elif path.startswith('/api/attachments/'):
            # Legacy support
            parts = path.split('/')
            if len(parts) >= 5:
                ticket_id = parts[3]
                filename = unquote(parts[4])
                self._handle_get_attachment_legacy(ticket_id, filename)
        elif path == '/api/database/tables':
            self._handle_get_db_tables()
        elif path.startswith('/api/database/table/'):
            parts = path.split('/')
            if len(parts) >= 5:
                table_name = parts[4]
                self._handle_get_table_data(table_name)
        else:
            self._send_json({'error': 'Not found'}, 404)
    
    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        if path == '/api/login':
            self._handle_login(body)
        elif path == '/api/logout':
            self._handle_logout()
        elif path == '/api/tickets':
            self._handle_create_ticket(body)
        elif path.startswith('/api/projects/') and '/tickets/' in path and path.endswith('/comments'):
            parts = path.split('/')
            if len(parts) >= 7:
                project_id = parts[3]
                ticket_id = parts[5]
                self._handle_add_comment_with_project(project_id, ticket_id, body)
        elif path.endswith('/comments'):
            parts = path.split('/')
            if len(parts) >= 4:
                ticket_id = parts[3]
                self._handle_add_comment(ticket_id, body)
        elif path.endswith('/attachments'):
            parts = path.split('/')
            if len(parts) >= 4:
                ticket_id = parts[3]
                self._handle_upload_attachment(ticket_id, body)
        elif path == '/api/projects':
            self._handle_create_project(body)
        elif path == '/api/database/query':
            self._handle_db_query(body)
        elif path.startswith('/api/database/table/') and path.endswith('/record'):
            parts = path.split('/')
            if len(parts) >= 5:
                table_name = parts[4]
                self._handle_db_insert(table_name, body)
        else:
            self._send_json({'error': 'Not found'}, 404)
    
    def do_PUT(self):
        """Handle PUT requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        if path == '/api/profile':
            self._handle_update_profile(body)
        elif path == '/api/password':
            self._handle_change_password(body)
        elif path.startswith('/api/projects/') and '/tickets/' in path:
            parts = path.split('/')
            if len(parts) >= 6:
                project_id = parts[3]
                ticket_id = parts[5]
                self._handle_update_ticket_with_project(project_id, ticket_id, body)
        elif path.startswith('/api/tickets/'):
            parts = path.split('/')
            if len(parts) >= 4:
                ticket_id = parts[3]
                self._handle_update_ticket(ticket_id, body)
        elif path.startswith('/api/comments/'):
            parts = path.split('/')
            if len(parts) >= 4:
                comment_id = parts[3]
                self._handle_update_comment(comment_id, body)
        elif path.startswith('/api/users/'):
            parts = path.split('/')
            if len(parts) >= 4:
                user_id = parts[3]
                self._handle_update_user_role(user_id, body)
        elif path.startswith('/api/database/table/') and '/record/' in path:
            parts = path.split('/')
            if len(parts) >= 7:
                table_name = parts[4]
                pk_value = parts[6]
                query_params = parse_qs(parsed_path.query)
                pk_column = query_params.get('pkColumn', [''])[0]
                if not pk_column:
                    # Try to get from body
                    try:
                        data = json.loads(body.decode('utf-8'))
                        pk_column = data.get('pkColumn', '')
                    except:
                        pass
                self._handle_db_update(table_name, pk_column, pk_value, body)
        else:
            self._send_json({'error': 'Not found'}, 404)
    
    def do_DELETE(self):
        """Handle DELETE requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path.startswith('/api/tickets/'):
            parts = path.split('/')
            if len(parts) >= 4:
                ticket_id = parts[3]
                self._handle_delete_ticket(ticket_id)
        elif path.startswith('/api/comments/'):
            parts = path.split('/')
            if len(parts) >= 4:
                comment_id = parts[3]
                self._handle_delete_comment(comment_id)
        elif path.startswith('/api/attachments/'):
            parts = path.split('/')
            if len(parts) >= 5:
                ticket_id = parts[3]
                filename = unquote(parts[4])
                self._handle_delete_attachment(ticket_id, filename)
        elif path.startswith('/api/database/table/') and '/record/' in path:
            parts = path.split('/')
            if len(parts) >= 7:
                table_name = parts[4]
                pk_value = parts[6]
                query_params = parse_qs(urlparse(self.path).query)
                pk_column = query_params.get('pkColumn', [''])[0]
                self._handle_db_delete(table_name, pk_column, pk_value)
        else:
            self._send_json({'error': 'Not found'}, 404)
    
    def _serve_file(self, filename, content_type):
        """Serve HTML file"""
        try:
            filepath = os.path.join(os.path.dirname(__file__), filename)
            with open(filepath, 'rb') as f:
                content = f.read()
            self._set_headers(200, content_type)
            self.wfile.write(content)
        except FileNotFoundError:
            self._send_json({'error': 'File not found'}, 404)
    
    # Authentication handlers
    def _handle_login(self, body):
        """Handle login request"""
        try:
            print("\n[LOGIN] Received login request")
            data = json.loads(body.decode('utf-8'))
            username = data.get('username')
            password = data.get('password')
            
            print(f"[LOGIN] Username: {username}")
            
            if not username or not password:
                print("[LOGIN] Missing username or password")
                self._send_json({'error': 'Username and password required'}, 400)
                return
            
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            conn.close()
            
            if user:
                print(f"[LOGIN] User found: {username}, role: {user['role']}")
                password_hash = hash_password(username, password)
                if user['password_hash'] == password_hash:
                    print("[LOGIN] Password correct")
                    user_info = {
                        'family_name': user['family_name'],
                        'given_name': user['given_name'],
                        'email': user['email'],
                        'mobile': user['mobile'],
                        'role': user['role']
                    }
                    session_id = create_session(username, user_info)
                    print(f"[LOGIN] Session created: {session_id}")
                    self._send_json({
                        'success': True,
                        'session_id': session_id,
                        'username': username,
                        'name': f"{user['given_name']} {user['family_name']}",
                        'role': user['role']
                    })
                    return
                else:
                    print("[LOGIN] Password incorrect")
            else:
                print(f"[LOGIN] User not found: {username}")
            
            self._send_json({'error': 'Invalid credentials'}, 401)
        except Exception as e:
            print(f"[LOGIN ERROR] {str(e)}")
            import traceback
            traceback.print_exc()
            self._send_json({'error': str(e)}, 500)
    
    def _handle_logout(self):
        """Handle logout request"""
        session_id = self._get_session_id()
        if session_id:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
            conn.commit()
            conn.close()
        self._send_json({'success': True})
    
    # Ticket handlers
    def _handle_get_tickets(self, query):
        """Get all tickets or search tickets"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            tickets = get_all_tickets()
            
            project_filter = query.get('project_id', [''])[0]
            if project_filter:
                project_lower = project_filter.lower()
                tickets = [t for t in tickets if str(t.get('project_id', '')).lower() == project_lower]

            search = query.get('search', [''])[0]
            if search:
                search_lower = search.lower()
                tickets = [t for t in tickets if 
                          search_lower in t.get('summary', '').lower() or 
                          search_lower in t.get('description', '').lower()]
            
            self._send_json({'tickets': tickets})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    def _handle_get_ticket(self, project_id, ticket_id):
        """Get single ticket with details"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            ticket = get_ticket(project_id, int(ticket_id))
            if not ticket:
                self._send_json({'error': 'Ticket not found'}, 404)
                return
            
            # Get attachments list with project prefix
            attachments_dir = os.path.join(ATTACHMENTS_DIR, f"{project_id}_{ticket_id}")
            attachments = []
            if os.path.exists(attachments_dir):
                for filename in os.listdir(attachments_dir):
                    filepath = os.path.join(attachments_dir, filename)
                    if os.path.isfile(filepath):
                        stat = os.stat(filepath)
                        attachments.append({
                            'filename': filename,
                            'size': stat.st_size,
                            'uploaded_at': datetime.fromtimestamp(stat.st_mtime).isoformat()
                        })
            
            ticket['attachments'] = attachments
            self._send_json({'ticket': ticket})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    def _handle_create_ticket(self, body):
        """Create new ticket"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            data = json.loads(body.decode('utf-8'))
            
            summary = data.get('summary', '').strip()
            project_id = data.get('project_id', '').strip()
            if not summary:
                self._send_json({'error': 'Summary is required'}, 400)
                return
            if not project_id:
                self._send_json({'error': 'Project is required'}, 400)
                return

            # Validate project exists
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM projects WHERE id = ?', (project_id,))
            exists = cursor.fetchone()
            conn.close()
            if not exists:
                self._send_json({'error': 'Project not found'}, 404)
                return
            
            ticket_data = {
                'summary': summary,
                'issue_type': data.get('issue_type', 'Task'),
                'priority': data.get('priority', 'K2'),
                'due_date': data.get('due_date'),
                'assignee': data.get('assignee'),
                'description': data.get('description', ''),
                'status': 'Triage',
                'creator': session['user_id'],
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'project_id': project_id,
                'links': data.get('links', []) if isinstance(data.get('links', []), list) else []
            }
            
            ticket_id = create_ticket(ticket_data)
            
            # Return the created ticket with all its data
            new_ticket = {
                'id': ticket_id,
                'project_id': project_id,
                'summary': ticket_data['summary'],
                'issue_type': ticket_data['issue_type'],
                'priority': ticket_data['priority'],
                'due_date': ticket_data.get('due_date'),
                'assignee': ticket_data.get('assignee'),
                'description': ticket_data.get('description', ''),
                'status': ticket_data['status'],
                'creator': ticket_data['creator'],
                'created_at': ticket_data['created_at'],
                'updated_at': ticket_data['updated_at'],
                'links': ticket_data.get('links', [])
            }
            
            self._send_json({'success': True, 'ticket_id': ticket_id, 'ticket': new_ticket}, 201)
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    def _handle_update_ticket_with_project(self, project_id, ticket_id, body):
        """Update existing ticket with project context"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            data = json.loads(body.decode('utf-8'))
            ticket = get_ticket(project_id, int(ticket_id))
            
            if not ticket:
                self._send_json({'error': 'Ticket not found'}, 404)
                return
            
            # Build updates
            updates = {}
            for field in ['summary', 'issue_type', 'priority', 'due_date', 'assignee', 'description', 'status']:
                if field in data:
                    updates[field] = data[field]
            if 'links' in data:
                updates['links'] = data['links'] if isinstance(data['links'], list) else []
            
            update_ticket(project_id, int(ticket_id), updates)
            self._send_json({'success': True})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    def _handle_update_ticket(self, ticket_id, body):
        """Update existing ticket"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            data = json.loads(body.decode('utf-8'))
            ticket = get_ticket(int(ticket_id))
            
            if not ticket:
                self._send_json({'error': 'Ticket not found'}, 404)
                return
            
            # Build updates
            updates = {}
            for field in ['summary', 'issue_type', 'priority', 'due_date', 'assignee', 'description', 'status', 'project_id']:
                if field in data:
                    updates[field] = data[field]
            if 'links' in data:
                updates['links'] = data['links'] if isinstance(data['links'], list) else []

            if 'project_id' in updates:
                proj = str(updates['project_id']).strip()
                if not proj:
                    self._send_json({'error': 'Project is required'}, 400)
                    return
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute('SELECT id FROM projects WHERE id = ?', (proj,))
                exists = cursor.fetchone()
                conn.close()
                if not exists:
                    self._send_json({'error': 'Project not found'}, 404)
                    return
            
            update_ticket(int(ticket_id), updates)
            self._send_json({'success': True})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    def _handle_delete_ticket(self, ticket_id):
        """Delete ticket"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            delete_ticket(int(ticket_id))
            self._send_json({'success': True})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    # Comment handlers
    def _handle_add_comment(self, ticket_id, body):
        """Add comment to ticket"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            data = json.loads(body.decode('utf-8'))
            content = (data.get('content', '') or '')
            content = content.replace('\r\n', '\n').replace('\r', '\n')

            if not content.strip():
                self._send_json({'error': 'Comment content is required'}, 400)
                return
            
            ticket = get_ticket_by_any_id(int(ticket_id))
            if not ticket:
                self._send_json({'error': 'Ticket not found'}, 404)
                return
            
            project_id = ticket['project_id']
            comment_id = add_comment(project_id, int(ticket_id), session['user_id'], content)
            self._send_json({'success': True, 'comment_id': comment_id}, 201)
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_add_comment_with_project(self, project_id, ticket_id, body):
        """Add comment with explicit project context"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            data = json.loads(body.decode('utf-8'))
            content = (data.get('content', '') or '')
            content = content.replace('\r\n', '\n').replace('\r', '\n')

            if not content.strip():
                self._send_json({'error': 'Comment content is required'}, 400)
                return
            
            ticket = get_ticket(project_id, int(ticket_id))
            if not ticket:
                self._send_json({'error': 'Ticket not found'}, 404)
                return
            
            comment_id = add_comment(project_id, int(ticket_id), session['user_id'], content)
            self._send_json({'success': True, 'comment_id': comment_id}, 201)
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_update_comment(self, comment_id, body):
        """Update a comment (author or root)"""
        session = self._verify_auth()
        if not session:
            return
        try:
            data = json.loads(body.decode('utf-8'))
            content = (data.get('content', '') or '')
            content = content.replace('\r\n', '\n').replace('\r', '\n')
            if not content.strip():
                self._send_json({'error': 'Content is required'}, 400)
                return
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM comments WHERE id = ?', (comment_id,))
            comment = cursor.fetchone()
            if not comment:
                conn.close()
                self._send_json({'error': 'Comment not found'}, 404)
                return
            if comment['author'] != session['user_id'] and session['user_info']['role'] < 3:
                conn.close()
                self._send_json({'error': 'Permission denied'}, 403)
                return
            cursor.execute('UPDATE comments SET content = ? WHERE id = ?', (content, comment_id))
            project_id = comment['project_id']
            ticket_table = get_ticket_table_name(project_id)
            cursor.execute(f'UPDATE {ticket_table} SET updated_at = ? WHERE id = ?', (datetime.now().isoformat(), comment['ticket_id']))
            conn.commit()
            conn.close()
            self._send_json({'success': True})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_delete_comment(self, comment_id):
        """Delete a comment (author or root)"""
        session = self._verify_auth()
        if not session:
            return
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM comments WHERE id = ?', (comment_id,))
            comment = cursor.fetchone()
            if not comment:
                conn.close()
                self._send_json({'error': 'Comment not found'}, 404)
                return
            if comment['author'] != session['user_id'] and session['user_info']['role'] < 3:
                conn.close()
                self._send_json({'error': 'Permission denied'}, 403)
                return
            cursor.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
            project_id = comment['project_id']
            ticket_table = get_ticket_table_name(project_id)
            cursor.execute(f'UPDATE {ticket_table} SET updated_at = ? WHERE id = ?', (datetime.now().isoformat(), comment['ticket_id']))
            conn.commit()
            conn.close()
            self._send_json({'success': True})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    # Attachment handlers
    def _handle_upload_attachment(self, ticket_id, body):
        """Handle file upload"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            data = json.loads(body.decode('utf-8'))
            filename = (data.get('filename') or '').strip()
            file_data = base64.b64decode(data.get('data', ''))
            
            safe_filename = os.path.basename(filename)
            if not safe_filename or not file_data:
                self._send_json({'error': 'Filename and data required'}, 400)
                return
            
            ticket = get_ticket_by_any_id(int(ticket_id))
            if not ticket:
                self._send_json({'error': 'Ticket not found'}, 404)
                return

            project_id = ticket['project_id']
            attachments_dir = os.path.join(ATTACHMENTS_DIR, f"{project_id}_{ticket_id}")
            os.makedirs(attachments_dir, exist_ok=True)
            
            file_path = os.path.join(attachments_dir, safe_filename)
            with open(file_path, 'wb') as f:
                f.write(file_data)
            
            # Update ticket timestamp
            update_ticket(project_id, int(ticket_id), {})
            
            self._send_json({'success': True, 'filename': safe_filename}, 201)
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    def _handle_get_attachment(self, ticket_id, filename):
        """Download attachment"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            safe_filename = os.path.basename(filename)
            ticket = get_ticket_by_any_id(int(ticket_id))
            if not ticket:
                self._send_json({'error': 'Ticket not found'}, 404)
                return
            attachments_dir = os.path.join(ATTACHMENTS_DIR, f"{ticket['project_id']}_{ticket_id}")
            file_path = os.path.join(attachments_dir, safe_filename)
            if not os.path.exists(file_path):
                self._send_json({'error': 'File not found'}, 404)
                return
            
            with open(file_path, 'rb') as f:
                content = f.read()
            
            content_type, _ = mimetypes.guess_type(safe_filename)

            # Manually set headers so we can add Content-Disposition before ending headers
            self.send_response(200)
            self.send_header('Content-type', content_type or 'application/octet-stream')
            self.send_header('Content-Disposition', f'attachment; filename="{safe_filename}"')
            # Preserve CORS headers for fetch-based downloads
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Session-Id')
            self.end_headers()

            self.wfile.write(content)
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_get_attachment_legacy(self, ticket_id, filename):
        """Legacy download: ticket_id-only path"""
        # Reuse the main handler logic; this keeps old URLs working
        self._handle_get_attachment(ticket_id, filename)

    def _handle_delete_attachment(self, ticket_id, filename):
        """Delete attachment from a ticket"""
        session = self._verify_auth()
        if not session:
            return

        try:
            safe_filename = os.path.basename(filename)
            if not safe_filename:
                self._send_json({'error': 'Invalid filename'}, 400)
                return

            ticket = get_ticket_by_any_id(int(ticket_id))
            if not ticket:
                self._send_json({'error': 'Ticket not found'}, 404)
                return
            project_id = ticket['project_id']
            attachments_dir = os.path.join(ATTACHMENTS_DIR, f"{project_id}_{ticket_id}")
            file_path = os.path.join(attachments_dir, safe_filename)
            if not os.path.exists(file_path):
                self._send_json({'error': 'File not found'}, 404)
                return

            os.remove(file_path)

            update_ticket(project_id, int(ticket_id), {})

            self._send_json({'success': True})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    def _handle_get_profile(self):
        """Fetch current user's profile"""
        session = self._verify_auth()
        if not session:
            return

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT username, family_name, given_name, email, mobile, role FROM users WHERE username = ?', (session['user_id'],))
            row = cursor.fetchone()
            conn.close()

            if not row:
                self._send_json({'error': 'User not found'}, 404)
                return

            profile = {
                'username': row['username'],
                'family_name': row['family_name'],
                'given_name': row['given_name'],
                'email': row['email'],
                'mobile': row['mobile'],
                'role': row['role']
            }

            self._send_json({'profile': profile})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_update_profile(self, body):
        """Update current user's profile fields"""
        session = self._verify_auth()
        if not session:
            return

        try:
            data = json.loads(body.decode('utf-8'))
            given_name = data.get('given_name', '').strip()
            family_name = data.get('family_name', '').strip()
            email = data.get('email', '').strip()
            mobile = data.get('mobile', '').strip()

            if not given_name or not family_name:
                self._send_json({'error': 'Given name and family name are required'}, 400)
                return

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET family_name = ?, given_name = ?, email = ?, mobile = ? WHERE username = ?',
                (family_name, given_name, email, mobile, session['user_id'])
            )
            conn.commit()
            conn.close()

            self._send_json({'success': True})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_change_password(self, body):
        """Change current user's password"""
        session = self._verify_auth()
        if not session:
            return

        try:
            data = json.loads(body.decode('utf-8'))
            current_password = data.get('current_password', '')
            new_password = data.get('new_password', '')

            if not current_password or not new_password:
                self._send_json({'error': 'Current and new passwords are required'}, 400)
                return

            if len(new_password) < 4:
                self._send_json({'error': 'Password must be at least 4 characters'}, 400)
                return

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash FROM users WHERE username = ?', (session['user_id'],))
            row = cursor.fetchone()

            if not row:
                conn.close()
                self._send_json({'error': 'User not found'}, 404)
                return

            current_hash = hash_password(session['user_id'], current_password)
            if row['password_hash'] != current_hash:
                conn.close()
                self._send_json({'error': 'Current password is incorrect'}, 403)
                return

            new_hash = hash_password(session['user_id'], new_password)
            cursor.execute('UPDATE users SET password_hash = ? WHERE username = ?', (new_hash, session['user_id']))
            # Invalidate other sessions for this user except current
            cursor.execute('DELETE FROM sessions WHERE username = ? AND session_id != ?', (session['user_id'], self._get_session_id()))
            conn.commit()
            conn.close()

            self._send_json({'success': True})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    # User handlers
    def _handle_get_users(self):
        """Get all users (for assignee dropdown)"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('SELECT username, family_name, given_name, email FROM users ORDER BY username')
            
            user_list = []
            for row in cursor.fetchall():
                user_list.append({
                    'username': row['username'],
                    'name': f"{row['given_name']} {row['family_name']}",
                    'email': row['email']
                })
            
            conn.close()
            self._send_json({'users': user_list})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    def _handle_get_all_users(self):
        """Get all users with full info (for user management)"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            # Only root and manager can view all users
            if session['user_info']['role'] < 2:
                self._send_json({'error': 'Insufficient permissions'}, 403)
                return
            
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users ORDER BY username')
            
            user_list = []
            for row in cursor.fetchall():
                user_list.append({
                    'id': row['username'],
                    'username': row['username'],
                    'family_name': row['family_name'],
                    'given_name': row['given_name'],
                    'email': row['email'],
                    'mobile': row['mobile'],
                    'role': row['role']
                })
            
            conn.close()
            self._send_json({'users': user_list})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    def _handle_update_user_role(self, user_id, body):
        """Update user role"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            data = json.loads(body.decode('utf-8'))
            new_role = data.get('role')
            
            if new_role is None:
                self._send_json({'error': 'Role is required'}, 400)
                return
            
            current_user_id = session['user_id']
            current_user_role = session['user_info']['role']
            
            # Only root and manager can update roles
            if current_user_role < 2:
                self._send_json({'error': 'Insufficient permissions'}, 403)
                return
            
            # Cannot modify root user
            if user_id == 'root':
                self._send_json({'error': 'Cannot modify root user'}, 403)
                return
            
            # Cannot modify self
            if user_id == current_user_id:
                self._send_json({'error': 'Cannot modify your own role'}, 403)
                return
            
            # Cannot assign role higher than or equal to own role
            if new_role >= current_user_role:
                self._send_json({'error': 'Cannot assign role equal to or higher than your own'}, 403)
                return
            
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('SELECT username FROM users WHERE username = ?', (user_id,))
            if not cursor.fetchone():
                conn.close()
                self._send_json({'error': 'User not found'}, 404)
                return
            
            # Update user role
            cursor.execute('UPDATE users SET role = ? WHERE username = ?', (new_role, user_id))
            conn.commit()
            conn.close()
            
            self._send_json({'success': True})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    # Project handlers
    def _handle_get_projects(self):
        """Get all projects"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM projects ORDER BY created_at DESC')
            
            projects = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            self._send_json({'projects': projects})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)
    
    def _handle_create_project(self, body):
        """Create new project"""
        session = self._verify_auth()
        if not session:
            return
        
        try:
            # Only root and manager can create projects
            if session['user_info']['role'] < 2:
                self._send_json({'error': 'Insufficient permissions'}, 403)
                return
            
            data = json.loads(body.decode('utf-8'))
            project_id = data.get('id', '').strip()
            project_name = data.get('name', '').strip() or project_id
            project_desc = data.get('description', '').strip()
            
            if not project_id:
                self._send_json({'error': 'Project ID is required'}, 400)
                return
            
            conn = get_db()
            cursor = conn.cursor()
            
            # Check if project ID already exists
            cursor.execute('SELECT id FROM projects WHERE id = ?', (project_id,))
            if cursor.fetchone():
                conn.close()
                self._send_json({'error': 'Project ID already exists'}, 400)
                return
            
            # Add new project
            created_at = datetime.now().isoformat()
            cursor.execute('''
                INSERT INTO projects (id, name, description, created_by, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (project_id, project_name, project_desc, session['user_id'], created_at))
            
            conn.commit()
            conn.close()
            
            new_project = {
                'id': project_id,
                'name': project_name,
                'description': project_desc,
                'created_by': session['user_id'],
                'created_at': created_at
            }
            
            self._send_json({'success': True, 'project': new_project}, 201)
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_get_db_tables(self):
        """Get list of all database tables"""
        session = self._verify_auth()
        if not session:
            return
        
        if session.get('user_info', {}).get('role', 0) < 2:
            self._send_json({'error': 'Unauthorized - Manager or Root access required'}, 403)
            return
        
        try:
            
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
            ''')
            
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            self._send_json({'tables': tables})
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_get_table_data(self, table_name):
        """Get all data from a specific table"""
        session = self._verify_auth()
        if not session:
            return
        
        if session.get('user_info', {}).get('role', 0) < 2:
            self._send_json({'error': 'Unauthorized - Manager or Root access required'}, 403)
            return
        
        try:
            
            # Validate table name to prevent SQL injection
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name=?
            ''', (table_name,))
            
            if not cursor.fetchone():
                conn.close()
                self._send_json({'error': 'Table not found'}, 404)
                return
            
            # Get table schema
            cursor.execute(f'PRAGMA table_info({table_name})')
            columns = [{'name': row[1], 'type': row[2], 'pk': row[5]} for row in cursor.fetchall()]
            
            # Get table data
            cursor.execute(f'SELECT * FROM {table_name}')
            rows = []
            for row in cursor.fetchall():
                rows.append(list(row))
            
            conn.close()
            
            self._send_json({
                'table': table_name,
                'columns': columns,
                'rows': rows
            })
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_db_query(self, body):
        """Execute a custom SQL query"""
        session = self._verify_auth()
        if not session:
            return
        
        if session.get('user_info', {}).get('role', 0) < 2:
            self._send_json({'error': 'Unauthorized - Manager or Root access required'}, 403)
            return
        
        try:
            body_data = json.loads(body.decode('utf-8'))
            query = body_data.get('query', '').strip()
            if not query:
                self._send_json({'error': 'Query is required'}, 400)
                return
            
            # Basic SQL injection prevention
            query_upper = query.upper()
            dangerous_keywords = ['DROP', 'TRUNCATE', 'ALTER']
            for keyword in dangerous_keywords:
                if keyword in query_upper:
                    self._send_json({'error': f'Dangerous operation "{keyword}" not allowed'}, 400)
                    return
            
            conn = get_db()
            cursor = conn.cursor()
            
            # Execute query
            cursor.execute(query)
            
            # Check if it's a SELECT query
            if query_upper.startswith('SELECT'):
                columns = [desc[0] for desc in cursor.description] if cursor.description else []
                rows = []
                for row in cursor.fetchall():
                    rows.append(list(row))
                conn.close()
                self._send_json({
                    'columns': columns,
                    'rows': rows,
                    'rowCount': len(rows)
                })
            else:
                # For INSERT, UPDATE, DELETE
                conn.commit()
                affected = cursor.rowcount
                conn.close()
                self._send_json({
                    'success': True,
                    'affectedRows': affected
                })
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_db_insert(self, table_name, body):
        """Insert a new record into a table"""
        session = self._verify_auth()
        if not session:
            return
        
        if session.get('user_info', {}).get('role', 0) < 2:
            self._send_json({'error': 'Unauthorized - Manager or Root access required'}, 403)
            return
        
        try:
            body_data = json.loads(body.decode('utf-8'))
            data = body_data.get('data', {})
            if not data:
                self._send_json({'error': 'Data is required'}, 400)
                return
            
            # Validate table name
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name=?
            ''', (table_name,))
            
            if not cursor.fetchone():
                conn.close()
                self._send_json({'error': 'Table not found'}, 404)
                return
            
            # Build INSERT query
            columns = list(data.keys())
            placeholders = ','.join(['?' for _ in columns])
            column_names = ','.join(columns)
            values = [data[col] for col in columns]
            
            query = f'INSERT INTO {table_name} ({column_names}) VALUES ({placeholders})'
            cursor.execute(query, values)
            conn.commit()
            
            new_id = cursor.lastrowid
            conn.close()
            
            self._send_json({
                'success': True,
                'id': new_id
            }, 201)
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_db_update(self, table_name, pk_column, pk_value, body):
        """Update a record in a table"""
        session = self._verify_auth()
        if not session:
            return
        
        if session.get('user_info', {}).get('role', 0) < 2:
            self._send_json({'error': 'Unauthorized - Manager or Root access required'}, 403)
            return
        
        try:
            body_data = json.loads(body.decode('utf-8'))
            data = body_data.get('data', {})
            
            # If pk_column not provided as parameter, try to get from body
            if not pk_column:
                pk_column = body_data.get('pkColumn', '')
            
            if not data or not pk_column:
                self._send_json({'error': 'Data and primary key column are required'}, 400)
                return
            
            # Validate table name
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name=?
            ''', (table_name,))
            
            if not cursor.fetchone():
                conn.close()
                self._send_json({'error': 'Table not found'}, 404)
                return
            
            # Build UPDATE query
            set_clause = ','.join([f'{col}=?' for col in data.keys()])
            values = list(data.values())
            values.append(pk_value)
            
            query = f'UPDATE {table_name} SET {set_clause} WHERE {pk_column}=?'
            cursor.execute(query, values)
            conn.commit()
            
            affected = cursor.rowcount
            conn.close()
            
            if affected == 0:
                self._send_json({'error': 'Record not found'}, 404)
            else:
                self._send_json({
                    'success': True,
                    'affectedRows': affected
                })
        except Exception as e:
            self._send_json({'error': str(e)}, 500)

    def _handle_db_delete(self, table_name, pk_column, pk_value):
        """Delete a record from a table"""
        session = self._verify_auth()
        if not session:
            return
        
        if session.get('user_info', {}).get('role', 0) < 2:
            self._send_json({'error': 'Unauthorized - Manager or Root access required'}, 403)
            return
        
        try:
            
            if not pk_column:
                self._send_json({'error': 'Primary key column is required'}, 400)
                return
            
            # Validate table name
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name=?
            ''', (table_name,))
            
            if not cursor.fetchone():
                conn.close()
                self._send_json({'error': 'Table not found'}, 404)
                return
            
            # Delete record
            query = f'DELETE FROM {table_name} WHERE {pk_column}=?'
            cursor.execute(query, (pk_value,))
            conn.commit()
            
            affected = cursor.rowcount
            conn.close()
            
            if affected == 0:
                self._send_json({'error': 'Record not found'}, 404)
            else:
                self._send_json({
                    'success': True,
                    'affectedRows': affected
                })
        except Exception as e:
            self._send_json({'error': str(e)}, 500)


def run_server(port=5000):
    """Start the HTTP server"""
    init_database()
    
    server_address = ('', port)
    httpd = HTTPServer(server_address, R4PManagerHandler)
    
    print(f"\n{'='*60}")
    print(f"R4 Project Manager Server")
    print(f"{'='*60}")
    print(f"Server running on port {port}")
    print(f"Access at: http://localhost:{port}")
    print(f"\nDefault credentials:")
    print(f"  Username: root")
    print(f"  Password: 0000")
    print(f"  Role: 3 (Root)")
    print(f"\nData storage:")
    print(f"  Database: {DB_FILE}")
    print(f"  Attachments: {ATTACHMENTS_DIR}")
    print(f"\nPress Ctrl+C to stop the server")
    print(f"{'='*60}\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\nShutting down server...")
        httpd.shutdown()


if __name__ == '__main__':
    run_server()
