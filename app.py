"""
Five-user group chat — single-file Flask app with SQLite (database.db).
"""
from __future__ import annotations

import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from dotenv import load_dotenv

load_dotenv() 

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.db"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=86400,
    MAX_CONTENT_LENGTH=4096,
)

PRECONFIGURED_USERS = (
    ("salehin", "MD ABU SALEHIN", "#e8a87c", "Salehin07"),
    ("talha", "Talha", "#85dcb8", "Talha07"),
    ("talhagf", "Talha`s GF", "#a8d8ea", "Talha_GF07"),
    ("someone", "Someone", "#c38d9e", "Someone07"),
    ("eden", "Eden Brooks", "#e27d60", "eden07"),
)

ONLINE_WINDOW_SECONDS = 45


# ---------------------------------------------------------------------------
# Database

# ---------------------------------------------------------------------------
def init_db() -> None:
    """Create database.db and schema if missing (dev + production)."""
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                accent_color TEXT NOT NULL,
                last_seen TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                edited_at TEXT,
                is_deleted INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_messages_created
                ON messages(created_at);
            """
        )
        for username, display_name, accent, password in PRECONFIGURED_USERS:
            row = conn.execute(
                "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
                (username,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO users (username, display_name, password_hash, accent_color)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        username,
                        display_name,
                        generate_password_hash(password, method="scrypt"),
                        accent,
                    ),
                )
        _migrate_schema(conn)
        conn.commit()


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Add columns to existing database.db without losing data."""
    msg_cols = {row[1] for row in conn.execute("PRAGMA table_info(messages)").fetchall()}
    if "is_deleted" not in msg_cols:
        conn.execute(
            "ALTER TABLE messages ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0"
        )
    if "edited_at" not in msg_cols:
        conn.execute("ALTER TABLE messages ADD COLUMN edited_at TEXT")
    if "updated_at" not in msg_cols:
        conn.execute("ALTER TABLE messages ADD COLUMN updated_at TEXT")
        conn.execute(
            "UPDATE messages SET updated_at = created_at WHERE updated_at IS NULL"
        )

    user_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "last_seen" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN last_seen TEXT")


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with get_db() as conn:
        return conn.execute(
            "SELECT id, username, display_name, accent_color FROM users WHERE id = ?",
            (uid,),
        ).fetchone()


def sanitize_message(body: str) -> str | None:
    text = (body or "").strip()
    if not text or len(text) > 2000:
        return None
    return text


def touch_presence(user_id: int) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET last_seen = datetime('now') WHERE id = ?",
            (user_id,),
        )
        conn.commit()


def clear_presence(user_id: int) -> None:
    with get_db() as conn:
        conn.execute("UPDATE users SET last_seen = NULL WHERE id = ?", (user_id,))
        conn.commit()


def _presence_roster() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, username, display_name, accent_color, last_seen
            FROM users ORDER BY id
            """
        ).fetchall()
    now = datetime.now(timezone.utc)
    roster = []
    for r in rows:
        online = False
        if r["last_seen"]:
            try:
                seen = datetime.strptime(r["last_seen"], "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc
                )
                online = (now - seen).total_seconds() <= ONLINE_WINDOW_SECONDS
            except ValueError:
                online = False
        roster.append(
            {
                "id": r["id"],
                "username": r["username"],
                "display_name": r["display_name"],
                "accent_color": r["accent_color"],
                "online": online,
            }
        )
    return roster


def _message_row_to_dict(row: sqlite3.Row) -> dict:
    deleted = bool(row["is_deleted"])
    edited = bool(row["edited_at"]) and not deleted
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "body": "" if deleted else row["body"],
        "created_at": row["created_at"],
        "display_name": row["display_name"],
        "accent_color": row["accent_color"],
        "deleted": deleted,
        "edited": edited,
    }


def _fetch_message(conn: sqlite3.Connection, msg_id: int) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT m.id, m.user_id, m.body, m.created_at, m.is_deleted, m.edited_at,
               m.updated_at, u.display_name, u.accent_color
        FROM messages m
        JOIN users u ON u.id = m.user_id
        WHERE m.id = ?
        """,
        (msg_id,),
    ).fetchone()


# ---------------------------------------------------------------------------
# Templates (embedded — single app.py)
# ---------------------------------------------------------------------------
BASE_STYLES = """
@import url('https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Outfit:wght@300;400;500;600;700&display=swap');

:root {
  --bg-deep: #0c1118;
  --bg-panel: #141c27;
  --bg-elevated: #1a2433;
  --border: rgba(255, 248, 240, 0.08);
  --text: #f4efe6;
  --text-muted: #8b9aab;
  --accent: #d4a574;
  --accent-glow: rgba(212, 165, 116, 0.35);
  --danger: #e85d5d;
  --radius: 14px;
  --font-display: 'Instrument Serif', Georgia, serif;
  --font-body: 'Outfit', system-ui, sans-serif;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html, body {
  min-height: 100vh;
  font-family: var(--font-body);
  background: var(--bg-deep);
  color: var(--text);
}

body::before {
  content: '';
  position: fixed;
  inset: 0;
  background:
    radial-gradient(ellipse 80% 50% at 20% -10%, rgba(212, 165, 116, 0.12), transparent),
    radial-gradient(ellipse 60% 40% at 90% 100%, rgba(100, 140, 180, 0.08), transparent),
    url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");
  pointer-events: none;
  z-index: 0;
}

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.flash-stack {
  position: fixed;
  top: 1rem;
  right: 1rem;
  z-index: 100;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  max-width: 320px;
}

.flash {
  padding: 0.75rem 1rem;
  border-radius: var(--radius);
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  font-size: 0.9rem;
  animation: slideIn 0.35s ease;
}

.flash.error { border-color: rgba(232, 93, 93, 0.5); color: #ffb4b4; }
.flash.success { border-color: rgba(133, 220, 184, 0.4); color: #b8f0d4; }

@keyframes slideIn {
  from { opacity: 0; transform: translateX(12px); }
  to { opacity: 1; transform: translateX(0); }
}
"""

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in — Circle of Five</title>
  <style>
""" + BASE_STYLES + """
    .login-wrap {
      position: relative;
      z-index: 1;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 2rem;
    }

    .login-card {
      width: min(420px, 100%);
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: calc(var(--radius) + 6px);
      padding: 2.5rem 2rem;
      box-shadow: 0 24px 80px rgba(0, 0, 0, 0.45);
    }

    .login-card h1 {
      font-family: var(--font-display);
      font-size: 2.4rem;
      font-weight: 400;
      line-height: 1.15;
      margin-bottom: 0.35rem;
    }

    .login-card .subtitle {
      color: var(--text-muted);
      font-size: 0.95rem;
      margin-bottom: 2rem;
    }

    .avatars {
      display: flex;
      gap: -8px;
      margin-bottom: 2rem;
    }

    .avatars span {
      width: 36px;
      height: 36px;
      border-radius: 50%;
      border: 2px solid var(--bg-panel);
      margin-left: -10px;
      display: grid;
      place-items: center;
      font-size: 0.7rem;
      font-weight: 600;
      color: var(--bg-deep);
    }
    .avatars span:first-child { margin-left: 0; }

    label {
      display: block;
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--text-muted);
      margin-bottom: 0.4rem;
    }

    input, select {
      width: 100%;
      padding: 0.85rem 1rem;
      margin-bottom: 1.25rem;
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--text);
      font-family: inherit;
      font-size: 1rem;
      transition: border-color 0.2s, box-shadow 0.2s;
    }

    input:focus, select:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-glow);
    }

    button[type="submit"] {
      width: 100%;
      padding: 0.95rem;
      margin-top: 0.5rem;
      border: none;
      border-radius: var(--radius);
      background: linear-gradient(135deg, #d4a574 0%, #b8864f 100%);
      color: #1a1208;
      font-family: inherit;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.15s, filter 0.15s;
    }

    button[type="submit"]:hover {
      filter: brightness(1.08);
      transform: translateY(-1px);
    }

    .hint {
      margin-top: 1.5rem;
      font-size: 0.8rem;
      color: var(--text-muted);
      text-align: center;
      line-height: 1.5;
    }
  </style>
</head>
<body>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
    <div class="flash-stack">
      {% for category, message in messages %}
      <div class="flash {{ category }}">{{ message }}</div>
      {% endfor %}
    </div>
    {% endif %}
  {% endwith %}

  <div class="login-wrap">
    <div class="login-card">
      <div class="avatars">
        {% for u in roster %}
        <span style="background: {{ u.accent_color }}" title="{{ u.display_name }}">
          {{ u.display_name[0] }}
        </span>
        {% endfor %}
      </div>
      <h1>Circle of Five</h1>
      <p class="subtitle">Private room for five members only.</p>

      <form method="post" action="{{ url_for('login') }}" autocomplete="off">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label for="username">Member</label>
        <select id="username" name="username" required>
          <option value="" disabled selected>Choose your identity…</option>
          {% for u in roster %}
          <option value="{{ u.username }}">{{ u.display_name }} (@{{ u.username }})</option>
          {% endfor %}
        </select>

        <label for="password">Password</label>
        <input id="password" name="password" type="password" required
               placeholder="Your member passphrase" minlength="1" maxlength="128">

        <button type="submit">Enter the room</button>
      </form>

      <p class="hint">Only registered members can view or send messages.<br>
      Demo passwords match each username’s theme (see README).</p>
    </div>
  </div>
</body>
</html>
"""

CHAT_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Chat — Circle of Five</title>
  <style>
""" + BASE_STYLES + """
    .app {
      position: relative;
      z-index: 1;
      max-width: 900px;
      margin: 0 auto;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      padding: 1.25rem;
    }

    header.bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 1rem 1.25rem;
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      margin-bottom: 1rem;
    }

    header.bar h1 {
      font-family: var(--font-display);
      font-size: 1.6rem;
      font-weight: 400;
    }

    header.bar .you {
      font-size: 0.85rem;
      color: var(--text-muted);
    }

    header.bar .you strong {
      color: var(--text);
    }

    .members {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-bottom: 1rem;
    }

    .member-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.35rem 0.75rem;
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 999px;
      font-size: 0.8rem;
    }

    .member-pill .avatar-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      flex-shrink: 0;
    }

    .member-pill .status-dot {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      flex-shrink: 0;
      box-shadow: 0 0 0 2px var(--bg-panel);
    }

    .member-pill .status-dot.online { background: #4ade80; }
    .member-pill .status-dot.offline { background: #6b7280; }

    .member-pill .status-label {
      font-size: 0.68rem;
      color: var(--text-muted);
      margin-left: -0.15rem;
    }

    .chat-panel {
      flex: 1;
      display: flex;
      flex-direction: column;
      min-height: 0;
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
    }

    #messages {
      flex: 1;
      overflow-y: auto;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.85rem;
      min-height: 320px;
      max-height: calc(100vh - 280px);
    }

    .msg {
      max-width: 82%;
      animation: msgIn 0.3s ease;
      position: relative;
    }

    @keyframes msgIn {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .msg.mine { align-self: flex-end; text-align: right; }

    .msg .meta {
      font-size: 0.72rem;
      color: var(--text-muted);
      margin-bottom: 0.25rem;
    }

    .msg .bubble {
      display: inline-block;
      padding: 0.75rem 1rem;
      border-radius: var(--radius);
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      line-height: 1.45;
      word-break: break-word;
      text-align: left;
    }

    .msg.mine .bubble {
      border-color: color-mix(in srgb, var(--mine-color) 40%, transparent);
      background: color-mix(in srgb, var(--mine-color) 18%, var(--bg-elevated));
    }

    .msg .edited-tag {
      display: block;
      margin-top: 0.35rem;
      font-size: 0.68rem;
      color: var(--text-muted);
      font-style: italic;
    }

    .msg-wrap {
      position: relative;
      display: inline-block;
      max-width: 100%;
      cursor: default;
    }

    .msg.mine .msg-wrap { cursor: pointer; }

    .msg.mine:hover .msg-actions,
    .msg.mine.actions-pinned .msg-actions {
      opacity: 1;
      pointer-events: auto;
      transform: translateY(0);
    }

    .msg.mine.actions-pinned .bubble {
      outline: 1px solid color-mix(in srgb, var(--mine-color) 55%, transparent);
      outline-offset: 2px;
    }

    .msg-actions {
      position: absolute;
      top: -2.15rem;
      right: 0;
      display: flex;
      gap: 0.35rem;
      opacity: 0;
      pointer-events: none;
      transform: translateY(4px);
      transition: opacity 0.15s, transform 0.15s;
      z-index: 5;
    }

    .msg:not(.mine) .msg-actions { display: none; }

    .msg-actions button {
      padding: 0.35rem 0.65rem;
      font-size: 0.72rem;
      font-family: inherit;
      font-weight: 600;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--bg-panel);
      color: var(--text);
      cursor: pointer;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);
    }

    .msg-actions button.delete {
      color: #ffb4b4;
      border-color: rgba(232, 93, 93, 0.35);
    }

    .msg-actions button:hover { filter: brightness(1.12); }

    @media (hover: none) and (pointer: coarse) {
      .msg.mine:hover .msg-actions { opacity: 0; pointer-events: none; }
      .msg.mine.actions-pinned .msg-actions {
        opacity: 1;
        pointer-events: auto;
        transform: translateY(0);
      }
    }

    .modal-backdrop {
      position: fixed;
      inset: 0;
      z-index: 200;
      display: grid;
      place-items: center;
      padding: 1.25rem;
      background: rgba(6, 10, 16, 0.72);
      backdrop-filter: blur(6px);
      animation: fadeIn 0.2s ease;
    }

    .modal-backdrop[hidden] { display: none !important; }

    .modal {
      width: min(400px, 100%);
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: calc(var(--radius) + 4px);
      padding: 1.5rem 1.35rem 1.25rem;
      box-shadow: 0 28px 64px rgba(0, 0, 0, 0.55);
      animation: modalUp 0.25s ease;
    }

    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }

    @keyframes modalUp {
      from { opacity: 0; transform: translateY(12px) scale(0.98); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }

    .modal h2 {
      font-family: var(--font-display);
      font-size: 1.45rem;
      font-weight: 400;
      margin-bottom: 0.5rem;
    }

    .modal .modal-desc {
      color: var(--text-muted);
      font-size: 0.9rem;
      line-height: 1.5;
      margin-bottom: 1rem;
    }

    .modal textarea {
      width: 100%;
      min-height: 100px;
      padding: 0.85rem 1rem;
      margin-bottom: 1.25rem;
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--text);
      font-family: inherit;
      font-size: 1rem;
      line-height: 1.45;
      resize: vertical;
    }

    .modal textarea:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-glow);
    }

    .modal-actions {
      display: flex;
      gap: 0.65rem;
      justify-content: flex-end;
    }

    .modal-btn {
      padding: 0.65rem 1.15rem;
      border-radius: var(--radius);
      font-family: inherit;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--bg-elevated);
      color: var(--text-muted);
      transition: filter 0.15s, color 0.15s;
    }

    .modal-btn:hover {
      color: var(--text);
      filter: brightness(1.08);
    }

    .modal-btn.primary {
      background: linear-gradient(135deg, #d4a574 0%, #b8864f 100%);
      color: #1a1208;
      border: none;
    }

    .modal-btn.danger {
      background: rgba(232, 93, 93, 0.18);
      color: #ffb4b4;
      border-color: rgba(232, 93, 93, 0.45);
    }

    .modal-btn.danger:hover {
      background: rgba(232, 93, 93, 0.28);
      color: #ffd0d0;
    }

    .composer {
      display: flex;
      gap: 0.65rem;
      padding: 1rem;
      border-top: 1px solid var(--border);
      background: var(--bg-elevated);
    }

    .composer input {
      flex: 1;
      padding: 0.85rem 1rem;
      background: var(--bg-deep);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--text);
      font-family: inherit;
      font-size: 1rem;
    }

    .composer input:focus {
      outline: none;
      border-color: var(--accent);
    }

    .composer button {
      padding: 0.85rem 1.35rem;
      border: none;
      border-radius: var(--radius);
      background: var(--mine-color, var(--accent));
      color: #0c1118;
      font-weight: 600;
      font-family: inherit;
      cursor: pointer;
      transition: filter 0.15s;
    }

    .composer button:hover { filter: brightness(1.1); }

    .logout-btn {
      padding: 0.5rem 1rem;
      font-size: 0.85rem;
      background: transparent;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--text-muted);
      font-family: inherit;
      cursor: pointer;
      text-decoration: none;
      transition: color 0.15s, border-color 0.15s;
    }

    .logout-btn:hover {
      color: var(--text);
      border-color: var(--text-muted);
      text-decoration: none;
    }

    .empty-state {
      color: var(--text-muted);
      text-align: center;
      padding: 3rem 1rem;
      font-style: italic;
    }
  </style>
</head>
<body>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
    <div class="flash-stack">
      {% for category, message in messages %}
      <div class="flash {{ category }}">{{ message }}</div>
      {% endfor %}
    </div>
    {% endif %}
  {% endwith %}

  <div class="app" style="--mine-color: {{ me.accent_color }}">
    <header class="bar">
      <div>
        <h1>Circle of Five</h1>
        <p class="you">Signed in as <strong>{{ me.display_name }}</strong></p>
      </div>
      <form method="post" action="{{ url_for('logout') }}" style="margin:0">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button type="submit" class="logout-btn">Sign out</button>
      </form>
    </header>

    <div class="members" id="member-list">
      {% for m in roster %}
      <span class="member-pill" data-user-id="{{ m.id }}">
        <span class="avatar-dot" style="background: {{ m.accent_color }}"></span>
        <span class="status-dot offline" data-status-dot aria-hidden="true"></span>
        {{ m.display_name }}
        <span class="status-label" data-status-label>offline</span>
      </span>
      {% endfor %}
    </div>

    <section class="chat-panel">
      <div id="messages" aria-live="polite">
        <p class="empty-state" id="empty-hint">No messages yet — say hello to the room.</p>
      </div>
      <form class="composer" id="send-form" autocomplete="off">
        <input type="hidden" name="csrf_token" id="csrf" value="{{ csrf_token() }}">
        <input type="text" id="body" name="body" maxlength="2000"
               placeholder="Message all four others…" required>
        <button type="submit">Send</button>
      </form>
    </section>
  </div>

  <div class="modal-backdrop" id="modal-backdrop" hidden>
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <h2 id="modal-title"></h2>
      <p class="modal-desc" id="modal-desc" hidden></p>
      <textarea id="modal-textarea" hidden maxlength="2000"></textarea>
      <div class="modal-actions">
        <button type="button" class="modal-btn" id="modal-cancel">Cancel</button>
        <button type="button" class="modal-btn primary" id="modal-confirm">Confirm</button>
      </div>
    </div>
  </div>

  <script>
    const meId = {{ me.id }};
    let lastId = 0;
    let lastSync = '';
    const knownIds = new Set();
    const listEl = document.getElementById('messages');
    const emptyHint = document.getElementById('empty-hint');
    const csrf = document.getElementById('csrf').value;
    const LONG_PRESS_MS = 500;
    let pinnedMsgEl = null;

    const modalBackdrop = document.getElementById('modal-backdrop');
    const modalTitle = document.getElementById('modal-title');
    const modalDesc = document.getElementById('modal-desc');
    const modalTextarea = document.getElementById('modal-textarea');
    const modalCancel = document.getElementById('modal-cancel');
    const modalConfirm = document.getElementById('modal-confirm');

    function escapeHtml(s) {
      const d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML;
    }

    function formatTime(createdAt) {
      const normalized = createdAt.includes('T') ? createdAt : createdAt.replace(' ', 'T') + 'Z';
      return new Date(normalized).toLocaleString(undefined, {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
      });
    }

    function bubbleHtml(m) {
      const edited = m.edited ? '<span class="edited-tag">(edited)</span>' : '';
      return `<div class="bubble">${escapeHtml(m.body)}${edited}</div>`;
    }

    function actionsHtml() {
      return `<div class="msg-actions" role="toolbar" aria-label="Message actions">
        <button type="button" class="edit-btn">Edit</button>
        <button type="button" class="delete-btn delete">Delete</button>
      </div>`;
    }

    function unpinAll() {
      document.querySelectorAll('.msg.mine.actions-pinned').forEach(el => {
        el.classList.remove('actions-pinned');
      });
      pinnedMsgEl = null;
    }

    function pinMessage(div) {
      if (pinnedMsgEl === div) return;
      unpinAll();
      div.classList.add('actions-pinned');
      pinnedMsgEl = div;
    }

    function closeModal() {
      modalBackdrop.hidden = true;
      document.body.style.overflow = '';
    }

    function openModal({ title, desc, mode, initialText, confirmLabel, danger, onConfirm }) {
      modalTitle.textContent = title;
      modalDesc.hidden = !desc;
      modalDesc.textContent = desc || '';
      modalTextarea.hidden = mode !== 'edit';
      modalConfirm.textContent = confirmLabel;
      modalConfirm.className = 'modal-btn ' + (danger ? 'danger' : 'primary');

      if (mode === 'edit') {
        modalTextarea.value = initialText || '';
        setTimeout(() => {
          modalTextarea.focus();
          modalTextarea.setSelectionRange(modalTextarea.value.length, modalTextarea.value.length);
        }, 50);
      }

      const handleConfirm = async () => {
        if (mode === 'edit') {
          const trimmed = modalTextarea.value.trim();
          if (!trimmed || trimmed === initialText) {
            closeModal();
            return;
          }
          await onConfirm(trimmed);
        } else {
          await onConfirm();
        }
        closeModal();
      };

      modalBackdrop.hidden = false;
      document.body.style.overflow = 'hidden';

      modalCancel.onclick = closeModal;
      modalConfirm.onclick = handleConfirm;
      modalBackdrop.onclick = (e) => {
        if (e.target === modalBackdrop) closeModal();
      };
    }

    function openEditModal(msgId, body) {
      openModal({
        title: 'Edit message',
        mode: 'edit',
        initialText: body,
        confirmLabel: 'Save changes',
        danger: false,
        onConfirm: (text) => apiMessage('PATCH', msgId, { body: text })
      });
    }

    function openDeleteModal(msgId) {
      openModal({
        title: 'Delete message?',
        desc: 'This removes the message for everyone in the room. You can’t undo this.',
        mode: 'delete',
        confirmLabel: 'Delete',
        danger: true,
        onConfirm: () => apiMessage('DELETE', msgId)
      });
    }

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !modalBackdrop.hidden) closeModal();
    });

    document.addEventListener('click', (e) => {
      if (modalBackdrop.hidden
          && !e.target.closest('.msg.mine')
          && !e.target.closest('.modal-backdrop')) {
        unpinAll();
      }
    });

    function bindMineActions(div, m) {
      if (m.user_id !== meId || m.deleted) return;
      const wrap = div.querySelector('.msg-wrap');
      let pressTimer = null;

      wrap.addEventListener('click', (e) => {
        if (e.target.closest('.msg-actions')) return;
        e.stopPropagation();
        pinMessage(div);
      });

      wrap.addEventListener('touchstart', (e) => {
        if (e.target.closest('.msg-actions')) return;
        pressTimer = setTimeout(() => {
          e.preventDefault();
          pinMessage(div);
        }, LONG_PRESS_MS);
      }, { passive: false });

      ['touchend', 'touchmove', 'touchcancel'].forEach(ev => {
        wrap.addEventListener(ev, () => clearTimeout(pressTimer));
      });

      div.querySelector('.edit-btn').addEventListener('click', (e) => {
        e.stopPropagation();
        openEditModal(m.id, m.body);
      });

      div.querySelector('.delete-btn').addEventListener('click', (e) => {
        e.stopPropagation();
        openDeleteModal(m.id);
      });
    }

    async function apiMessage(method, id, payload) {
      const res = await fetch(`/api/messages/${id}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrf
        },
        credentials: 'same-origin',
        body: payload ? JSON.stringify(payload) : undefined
      });
      if (res.status === 401) {
        window.location.href = '{{ url_for("login") }}';
        return;
      }
      if (res.ok) {
        const data = await res.json();
        if (data.message) applyMessage(data.message);
      }
    }

    function removeMessage(id) {
      const el = listEl.querySelector(`.msg[data-id="${id}"]`);
      if (el) el.remove();
      knownIds.delete(id);
      if (!listEl.querySelector('.msg') && !document.getElementById('empty-hint')) {
        const p = document.createElement('p');
        p.className = 'empty-state';
        p.id = 'empty-hint';
        p.textContent = 'No messages yet — say hello to the room.';
        listEl.appendChild(p);
      }
    }

    function applyMessage(m) {
      if (m.deleted) {
        removeMessage(m.id);
        return;
      }

      if (emptyHint) emptyHint.remove();
      let div = listEl.querySelector(`.msg[data-id="${m.id}"]`);
      const isNew = !div;

      if (isNew) {
        div = document.createElement('div');
        div.dataset.id = m.id;
        listEl.appendChild(div);
        knownIds.add(m.id);
        lastId = Math.max(lastId, m.id);
      }

      const wasPinned = div.classList?.contains('actions-pinned');
      div.className = 'msg' + (m.user_id === meId ? ' mine' : '');
      if (wasPinned) div.classList.add('actions-pinned');
      const time = formatTime(m.created_at);
      const mineActions = m.user_id === meId ? actionsHtml() : '';
      div.innerHTML = `
        <div class="meta">${escapeHtml(m.display_name)} · ${time}</div>
        <div class="msg-wrap">
          ${mineActions}
          ${bubbleHtml(m)}
        </div>`;
      bindMineActions(div, m);
      if (wasPinned) pinnedMsgEl = div;

      if (isNew) listEl.scrollTop = listEl.scrollHeight;
    }

    function updatePresence(members) {
      (members || []).forEach(m => {
        const pill = document.querySelector(`.member-pill[data-user-id="${m.id}"]`);
        if (!pill) return;
        const dot = pill.querySelector('[data-status-dot]');
        const label = pill.querySelector('[data-status-label]');
        dot.classList.toggle('online', m.online);
        dot.classList.toggle('offline', !m.online);
        label.textContent = m.online ? 'online' : 'offline';
      });
    }

    async function fetchMessages() {
      try {
        const params = new URLSearchParams({ after: String(lastId) });
        if (lastSync) params.set('since', lastSync);
        const res = await fetch(`{{ url_for('api_messages') }}?${params}`, {
          credentials: 'same-origin'
        });
        if (res.status === 401) {
          window.location.href = '{{ url_for("login") }}';
          return;
        }
        const data = await res.json();
        if (data.server_time) lastSync = data.server_time;
        updatePresence(data.presence);
        (data.messages || []).forEach(m => {
          if (!knownIds.has(m.id)) applyMessage(m);
        });
        (data.updates || []).forEach(applyMessage);
      } catch (_) { /* retry on next poll */ }
    }

    document.getElementById('send-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = document.getElementById('body');
      const body = input.value.trim();
      if (!body) return;
      const res = await fetch('{{ url_for("api_send") }}', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrf
        },
        credentials: 'same-origin',
        body: JSON.stringify({ body })
      });
      if (res.ok) {
        input.value = '';
        const data = await res.json();
        if (data.message) applyMessage(data.message);
      } else if (res.status === 401) {
        window.location.href = '{{ url_for("login") }}';
      }
    });

    fetchMessages();
    setInterval(fetchMessages, 2500);
  </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CSRF (lightweight, session-bound)
# ---------------------------------------------------------------------------
def csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def validate_csrf() -> bool:
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get("_csrf")
    return bool(token and expected and secrets.compare_digest(token, expected))


app.jinja_env.globals["csrf_token"] = csrf_token


# ---------------------------------------------------------------------------
# Routes — nothing public except login + static assets (none)
# ---------------------------------------------------------------------------
@app.before_request
def ensure_db():
    if not DB_PATH.exists():
        init_db()
    else:
        with get_db() as conn:
            _migrate_schema(conn)
            conn.commit()


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("chat"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("chat"))

    roster = _roster()

    if request.method == "POST":
        if not validate_csrf():
            flash("Invalid session. Please try again.", "error")
            return render_template_string(LOGIN_PAGE, roster=roster), 400

        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""

        with get_db() as conn:
            user = conn.execute(
                """
                SELECT id, username, display_name, password_hash, accent_color
                FROM users WHERE username = ? COLLATE NOCASE
                """,
                (username,),
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["_csrf"] = secrets.token_urlsafe(32)
            touch_presence(user["id"])
            flash(f"Welcome back, {user['display_name']}.", "success")
            return redirect(url_for("chat"))

        flash("Wrong member or password.", "error")

    return render_template_string(LOGIN_PAGE, roster=roster)


@app.route("/logout", methods=["POST"])
def logout():
    if not validate_csrf():
        abort(400)
    uid = session.get("user_id")
    if uid:
        clear_presence(uid)
    session.clear()
    flash("You have signed out.", "success")
    return redirect(url_for("login"))


@app.route("/chat")
@login_required
def chat():
    me = current_user()
    if not me:
        session.clear()
        return redirect(url_for("login"))
    roster = _roster()
    return render_template_string(CHAT_PAGE, me=me, roster=roster)


@app.route("/api/messages")
@login_required
def api_messages():
    touch_presence(session["user_id"])
    after = request.args.get("after", 0, type=int)
    since = (request.args.get("since") or "").strip()
    if after < 0:
        after = 0

    with get_db() as conn:
        server_time = conn.execute("SELECT datetime('now') AS t").fetchone()["t"]
        rows = conn.execute(
            """
            SELECT m.id, m.user_id, m.body, m.created_at, m.is_deleted, m.edited_at,
                   u.display_name, u.accent_color
            FROM messages m
            JOIN users u ON u.id = m.user_id
            WHERE m.id > ?
            ORDER BY m.id ASC
            LIMIT 200
            """,
            (after,),
        ).fetchall()

        updates = []
        if since:
            updates = conn.execute(
                """
                SELECT m.id, m.user_id, m.body, m.created_at, m.is_deleted, m.edited_at,
                       u.display_name, u.accent_color
                FROM messages m
                JOIN users u ON u.id = m.user_id
                WHERE m.updated_at > ? AND m.id <= ?
                ORDER BY m.id ASC
                LIMIT 200
                """,
                (since, after if after else 999999999),
            ).fetchall()

    return jsonify({
        "server_time": server_time,
        "presence": _presence_roster(),
        "messages": [_message_row_to_dict(r) for r in rows],
        "updates": [_message_row_to_dict(r) for r in updates],
    })


@app.route("/api/send", methods=["POST"])
@login_required
def api_send():
    if not validate_csrf():
        return jsonify({"error": "invalid csrf"}), 400

    payload = request.get_json(silent=True) or {}
    body = sanitize_message(payload.get("body", ""))
    if body is None:
        return jsonify({"error": "invalid message"}), 400

    uid = session["user_id"]
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO messages (user_id, body) VALUES (?, ?)",
            (uid, body),
        )
        msg_id = cur.lastrowid
        row = _fetch_message(conn, msg_id)
        conn.commit()

    return jsonify({"message": _message_row_to_dict(row)})


@app.route("/api/messages/<int:msg_id>", methods=["PATCH", "DELETE"])
@login_required
def api_message_modify(msg_id: int):
    if not validate_csrf():
        return jsonify({"error": "invalid csrf"}), 400

    uid = session["user_id"]
    with get_db() as conn:
        existing = conn.execute(
            "SELECT id, user_id, is_deleted FROM messages WHERE id = ?",
            (msg_id,),
        ).fetchone()
        if not existing or existing["user_id"] != uid:
            return jsonify({"error": "not found"}), 404
        if existing["is_deleted"]:
            return jsonify({"error": "gone"}), 410

        if request.method == "DELETE":
            conn.execute(
                """
                UPDATE messages
                SET is_deleted = 1, updated_at = datetime('now')
                WHERE id = ?
                """,
                (msg_id,),
            )
        else:
            payload = request.get_json(silent=True) or {}
            body = sanitize_message(payload.get("body", ""))
            if body is None:
                return jsonify({"error": "invalid message"}), 400
            conn.execute(
                """
                UPDATE messages
                SET body = ?, edited_at = datetime('now'), updated_at = datetime('now')
                WHERE id = ?
                """,
                (body, msg_id),
            )

        row = _fetch_message(conn, msg_id)
        conn.commit()

    return jsonify({"message": _message_row_to_dict(row)})


def _roster():
    with get_db() as conn:
        return conn.execute(
            "SELECT id, username, display_name, accent_color FROM users ORDER BY id"
        ).fetchall()


# Block stray paths for anonymous users
@app.route("/<path:unknown>")
def catch_all(unknown):
    if unknown.startswith("api/"):
        return jsonify({"error": "not found"}), 404
    if not session.get("user_id"):
        return redirect(url_for("login"))
    abort(404)


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------
init_db()

if __name__ == "__main__":
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=debug)
