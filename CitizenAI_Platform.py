""" Citizen AI — Intelligent Citizen Engagement Platform Single-file Flask application for demo / prototype purposes.

Features:

User registration & login (passwords hashed)

Submit civic issues (title, description, category, location)

Upvote issues

Comment on issues

Simple admin dashboard

SQLite persistence (file: citizen_ai.db)

Single-file: templates rendered with render_template_string for easy copying


Run: pip install flask python CitizenAI_Platform.py

Then open http://127.0.0.1:5000 in your browser.

This is a demo/prototype. For production, add CSRF protection, input validation, rate-limiting, email verification, stronger auth, and deploy behind HTTPS. """ from flask import Flask, g, render_template_string, request, redirect, url_for, session, flash, jsonify import sqlite3 from werkzeug.security import generate_password_hash, check_password_hash from datetime import datetime import os

DB_PATH = 'citizen_ai.db' SECRET_KEY = os.environ.get('CITIZEN_AI_SECRET', 'dev-secret-key')

app = Flask(name) app.config['SECRET_KEY'] = SECRET_KEY

---------- Database helpers ----------

def get_db(): db = getattr(g, '_database', None) if db is None: db = g._database = sqlite3.connect(DB_PATH) db.row_factory = sqlite3.Row return db

@app.teardown_appcontext def close_connection(exception): db = getattr(g, '_database', None) if db is not None: db.close()

def init_db(): db = get_db() cur = db.cursor() cur.executescript(''' CREATE TABLE IF NOT EXISTS users ( id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, display_name TEXT, is_admin INTEGER DEFAULT 0, created_at TEXT );

CREATE TABLE IF NOT EXISTS issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT,
    location TEXT,
    author_id INTEGER,
    created_at TEXT,
    upvotes INTEGER DEFAULT 0,
    FOREIGN KEY(author_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_id INTEGER NOT NULL,
    author_id INTEGER,
    text TEXT NOT NULL,
    created_at TEXT,
    FOREIGN KEY(issue_id) REFERENCES issues(id),
    FOREIGN KEY(author_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TEXT,
    UNIQUE(issue_id, user_id),
    FOREIGN KEY(issue_id) REFERENCES issues(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
);
''')
db.commit()

Initialize DB when script starts (if not exists)

with app.app_context(): init_db()

---------- Simple auth helpers ----------

def current_user(): uid = session.get('user_id') if not uid: return None db = get_db() user = db.execute('SELECT id, username, display_name, is_admin FROM users WHERE id = ?', (uid,)).fetchone() return user

---------- Templates (render_template_string for single-file) ----------

BASE_HTML = ''' <!doctype html>

<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Citizen AI — Intelligent Citizen Engagement Platform</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body { padding-top: 4.5rem; }
      .issue-card { margin-bottom: 1rem; }
    </style>
  </head>
  <body>
    <nav class="navbar navbar-expand-md navbar-dark bg-primary fixed-top">
      <div class="container-fluid">
        <a class="navbar-brand" href="{{ url_for('index') }}">Citizen AI</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarsExampleDefault">
          <span class="navbar-toggler-icon"></span>
        </button><div class="collapse navbar-collapse" id="navbarsExampleDefault">
      <ul class="navbar-nav me-auto mb-2 mb-md-0">
        <li class="nav-item"><a class="nav-link" href="{{ url_for('index') }}">Home</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('submit_issue') }}">Submit Issue</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('about') }}">About</a></li>
      </ul>
      <ul class="navbar-nav ms-auto">
        {% if user %}
          <li class="nav-item"><a class="nav-link">Hi, {{ user['display_name'] or user['username'] }}</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
        {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">Register</a></li>
        {% endif %}
      </ul>
    </div>
  </div>
</nav>

<main class="container">
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="alert alert-info" role="alert">{{ messages[0] }}</div>
    {% endif %}
  {% endwith %}

  {% block content %}{% endblock %}
</main>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>

  </body>
</html>
'''INDEX_HTML = ''' {% extends base %} {% block content %}

  <div class="d-flex justify-content-between align-items-center mb-3">
    <h1>Citizen AI — Intelligent Citizen Engagement Platform</h1>
    <form class="d-flex" method="get" action="{{ url_for('index') }}">
      <input class="form-control me-2" name="q" placeholder="Search issues..." value="{{ request.args.get('q','') }}">
      <button class="btn btn-outline-secondary" type="submit">Search</button>
    </form>
  </div>  <div class="mb-3">
    <small class="text-muted">Report civic issues, discuss, and upvote what matters to you.</small>
  </div>{% for issue in issues %}

  <div class="card issue-card">
    <div class="card-body">
      <h5 class="card-title"><a href="{{ url_for('view_issue', issue_id=issue['id']) }}">{{ issue['title'] }}</a></h5>
      <h6 class="card-subtitle mb-2 text-muted">{{ issue['category'] or 'General' }} • {{ issue['location'] or 'Unknown' }} • reported {{ issue['created_at'] }}</h6>
      <p class="card-text">{{ issue['description'][:300] }}{% if issue['description']|length > 300 %}...{% endif %}</p>
      <div class="d-flex justify-content-between">
        <div>
          <small class="text-muted">By {{ issue['author_name'] or 'Anonymous' }}</small>
        </div>
        <div>
          <form method="post" action="{{ url_for('vote_issue', issue_id=issue['id']) }}" style="display:inline;">
            <button class="btn btn-sm btn-outline-success" type="submit">▲ Upvote ({{ issue['upvotes'] }})</button>
          </form>
          <a class="btn btn-sm btn-outline-primary" href="{{ url_for('view_issue', issue_id=issue['id']) }}">Comments</a>
        </div>
      </div>
    </div>
  </div>
  {% else %}
    <p>No issues found.</p>
  {% endfor %}{% endblock %} '''

VIEW_ISSUE_HTML = ''' {% extends base %} {% block content %}

  <h2>{{ issue['title'] }}</h2>
  <p class="text-muted">{{ issue['category'] or 'General' }} • {{ issue['location'] or 'Unknown' }} • reported {{ issue['created_at'] }}</p>
  <p>{{ issue['description'] }}</p>
  <p><strong>Upvotes:</strong> {{ issue['upvotes'] }}</p>  <div class="mb-3">
    <form method="post" action="{{ url_for('vote_issue', issue_id=issue['id']) }}">
      <button class="btn btn-success">▲ Upvote</button>
    </form>
  </div>  <hr>
  <h4>Comments</h4>
  {% for c in comments %}
    <div class="mb-2">
      <strong>{{ c['author_name'] or 'Anonymous' }}</strong> <small class="text-muted">{{ c['created_at'] }}</small>
      <div>{{ c['text'] }}</div>
    </div>
  {% else %}
    <p>No comments yet.</p>
  {% endfor %}{% if user %} <form method="post" action="{{ url_for('add_comment', issue_id=issue['id']) }}"> <div class="mb-3"> <label class="form-label">Your comment</label> <textarea class="form-control" name="text" rows="3" required></textarea> </div> <button class="btn btn-primary">Post Comment</button> </form> {% else %} <p><a href="{{ url_for('login') }}">Login</a> to comment.</p> {% endif %}

  <p class="mt-4"><a href="{{ url_for('index') }}">← Back to issues</a></p>
{% endblock %}
'''SUBMIT_HTML = ''' {% extends base %} {% block content %}

  <h2>Submit a Civic Issue</h2>
  {% if not user %}
    <p><a href="{{ url_for('login') }}">Login</a> or <a href="{{ url_for('register') }}">Register</a> to submit issues (you may also submit anonymously).</p>
  {% endif %}
  <form method="post" action="{{ url_for('submit_issue') }}">
    <div class="mb-3">
      <label class="form-label">Title</label>
      <input class="form-control" name="title" required>
    </div>
    <div class="mb-3">
      <label class="form-label">Category</label>
      <input class="form-control" name="category" placeholder="e.g., Road, Sanitation, Water">
    </div>
    <div class="mb-3">
      <label class="form-label">Location</label>
      <input class="form-control" name="location" placeholder="Neighborhood / Landmark">
    </div>
    <div class="mb-3">
      <label class="form-label">Description</label>
      <textarea class="form-control" name="description" rows="6" required></textarea>
    </div>
    <button class="btn btn-primary">Submit Issue</button>
  </form>
{% endblock %}
'''AUTH_HTML = ''' {% extends base %} {% block content %}

  <h2>{{ title }}</h2>
  <form method="post">
    <div class="mb-3">
      <label class="form-label">Username</label>
      <input class="form-control" name="username" required>
    </div>
    {% if register %}
      <div class="mb-3">
        <label class="form-label">Display name (optional)</label>
        <input class="form-control" name="display_name">
      </div>
    {% endif %}
    <div class="mb-3">
      <label class="form-label">Password</label>
      <input type="password" class="form-control" name="password" required>
    </div>
    <button class="btn btn-primary">{{ button_text }}</button>
  </form>
{% endblock %}
'''ABOUT_HTML = ''' {% extends base %} {% block content %}

  <h2>About Citizen AI</h2>
  <p>This prototype demonstrates a simple citizen engagement platform where community members can report issues, discuss, and prioritize problems through upvotes and comments. "AI" elements can be extended later (auto-categorization, suggestion ranking, summarization, routing to departments).</p>
  <p>For production use: ensure security hardening, proper authentication, logging, and integrations.</p>
{% endblock %}
'''ADMIN_HTML = ''' {% extends base %} {% block content %}

  <h2>Admin Dashboard</h2>
  <h4>Recent issues</h4>
  <ul>
  {% for i in issues %}
    <li>{{ i['created_at'] }} — {{ i['title'] }} ({{ i['upvotes'] }} upvotes) — <a href="{{ url_for('view_issue', issue_id=i['id']) }}">view</a></li>
  {% endfor %}
  </ul>
{% endblock %}
'''---------- Routes ----------

@app.context_processor def inject_base(): return dict(base=BASE_HTML, user=current_user(), request=request)

@app.route('/') def index(): q = request.args.get('q', '').strip() db = get_db() if q: rows = db.execute("SELECT issues., users.display_name as author_name FROM issues LEFT JOIN users ON users.id = issues.author_id WHERE issues.title LIKE ? OR issues.description LIKE ? ORDER BY issues.upvotes DESC, issues.created_at DESC", ('%'+q+'%', '%'+q+'%')).fetchall() else: rows = db.execute('SELECT issues., users.display_name as author_name FROM issues LEFT JOIN users ON users.id = issues.author_id ORDER BY issues.upvotes DESC, issues.created_at DESC').fetchall() issues = [dict(r) for r in rows] return render_template_string(INDEX_HTML, issues=issues)

@app.route('/issue/int:issue_id') def view_issue(issue_id): db = get_db() issue = db.execute('SELECT issues., users.display_name as author_name FROM issues LEFT JOIN users ON users.id = issues.author_id WHERE issues.id = ?', (issue_id,)).fetchone() if not issue: flash('Issue not found.') return redirect(url_for('index')) comments = db.execute('SELECT comments., users.display_name as author_name FROM comments LEFT JOIN users ON users.id = comments.author_id WHERE issue_id = ? ORDER BY created_at ASC', (issue_id,)).fetchall() return render_template_string(VIEW_ISSUE_HTML, issue=dict(issue), comments=[dict(c) for c in comments])

@app.route('/issue/int:issue_id/comment', methods=['POST']) def add_comment(issue_id): user = current_user() text = request.form.get('text','').strip() if not text: flash('Comment cannot be empty') return redirect(url_for('view_issue', issue_id=issue_id)) db = get_db() db.execute('INSERT INTO comments (issue_id, author_id, text, created_at) VALUES (?, ?, ?, ?)', (issue_id, user['id'] if user else None, text, datetime.utcnow().isoformat())) db.commit() flash('Comment posted') return redirect(url_for('view_issue', issue_id=issue_id))

@app.route('/submit', methods=['GET','POST']) def submit_issue(): user = current_user() if request.method == 'POST': title = request.form.get('title','').strip() category = request.form.get('category','').strip() location = request.form.get('location','').strip() description = request.form.get('description','').strip() if not title or not description: flash('Title and description are required') return redirect(url_for('submit_issue')) db = get_db() db.execute('INSERT INTO issues (title, description, category, location, author_id, created_at) VALUES (?, ?, ?, ?, ?, ?)', (title, description, category, location, user['id'] if user else None, datetime.utcnow().isoformat())) db.commit() flash('Issue submitted — thank you!') return redirect(url_for('index')) return render_template_string(SUBMIT_HTML)

@app.route('/vote/int:issue_id', methods=['POST']) def vote_issue(issue_id): user = current_user() db = get_db() if not user: flash('You must be logged in to vote') return redirect(url_for('login')) try: db.execute('INSERT INTO votes (issue_id, user_id, created_at) VALUES (?, ?, ?)', (issue_id, user['id'], datetime.utcnow().isoformat())) db.execute('UPDATE issues SET upvotes = upvotes + 1 WHERE id = ?', (issue_id,)) db.commit() flash('Upvoted') except sqlite3.IntegrityError: flash('You already voted for this issue') return redirect(request.referrer or url_for('index'))

Auth routes

@app.route('/register', methods=['GET','POST']) def register(): if request.method == 'POST': username = request.form.get('username','').strip() password = request.form.get('password','') display_name = request.form.get('display_name','').strip() if not username or not password: flash('Username and password required') return redirect(url_for('register')) db = get_db() try: db.execute('INSERT INTO users (username, password_hash, display_name, created_at) VALUES (?, ?, ?, ?)', (username, generate_password_hash(password), display_name or None, datetime.utcnow().isoformat())) db.commit() flash('Registration successful — please log in') return redirect(url_for('login')) except sqlite3.IntegrityError: flash('Username already exists') return redirect(url_for('register')) return render_template_string(AUTH_HTML, title='Register', register=True, button_text='Create account')

@app.route('/login', methods=['GET','POST']) def login(): if request.method == 'POST': username = request.form.get('username','').strip() password = request.form.get('password','') db = get_db() user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone() if user and check_password_hash(user['password_hash'], password): session['user_id'] = user['id'] flash('Logged in') return redirect(url_for('index')) flash('Invalid credentials') return redirect(url_for('login')) return render_template_string(AUTH_HTML, title='Login', register=False, button_text='Login')

@app.route('/logout') def logout(): session.pop('user_id', None) flash('Logged out') return redirect(url_for('index'))

Admin

@app.route('/admin') def admin(): user = current_user() if not user or not user['is_admin']: flash('Admin access required') return redirect(url_for('login')) db = get_db() rows = db.execute('SELECT * FROM issues ORDER BY created_at DESC LIMIT 50').fetchall() issues = [dict(r) for r in rows] return render_template_string(ADMIN_HTML, issues=issues)

Simple API endpoint for issues (JSON)

@app.route('/api/issues') def api_issues(): db = get_db() rows = db.execute('SELECT issues.id, title, description, category, location, upvotes, created_at FROM issues ORDER BY upvotes DESC, created_at DESC').fetchall() return jsonify([dict(r) for r in rows])

---------- Create a default admin user if none exists ----------

with app.app_context(): db = get_db() admin_exists = db.execute('SELECT 1 FROM users WHERE is_admin = 1').fetchone() if not admin_exists: try: db.execute('INSERT INTO users (username, password_hash, display_name, is_admin, created_at) VALUES (?, ?, ?, ?, ?)', ('admin', generate_password_hash('adminpass'), 'Administrator', 1, datetime.utcnow().isoformat())) db.commit() print('Created default admin -> username: admin password: adminpass') except Exception: pass

if name == 'main': app.run(debug=True)

