# Circle of Five — Flask group chat

Private chat room for **five preconfigured members**. Messages are stored in **`database.db`** (SQLite). No external database server.

## Quick start

```bash
cd c:\Users\ASUS\my_web\CHAT
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 — you will be redirected to login. Nothing else is visible without signing in.

## Demo accounts

| Member   | Username | Password   |
|----------|----------|------------|
| Alex Rivera  | `alex`  | `rivera7`  |
| Blake Chen   | `blake` | `chenwave` |
| Casey Morgan | `casey` | `morgan88` |
| Drew Patel   | `drew`  | `patelchat`|
| Eden Brooks  | `eden`  | `brookslive`|

## Production

```bash
set FLASK_ENV=production
set FLASK_SECRET_KEY=your-long-random-secret
python app.py
```

Or use a WSGI server (e.g. `waitress-serve --listen=*:5000 app:app`).

`database.db` is created automatically on first run if it does not exist.

## Features

- **Online / offline** — green dot and “online” label when a member was active in the last 45 seconds; grey when offline (updates every 2.5s).
- **Edit / delete** — on your own messages: hover **Edit** / **Delete** on desktop; **long-press** (~0.5s) on phone. Deleted messages disappear for everyone; edited messages show *(edited)* under the text.

## Security notes

- Passwords are hashed with **scrypt** (Werkzeug).
- Sessions are HTTP-only; CSRF tokens protect login, logout, send, edit, and delete.
- All chat and API routes require an active session.
- Logout clears the session and marks you offline (POST only).
