from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

DB_PATH = "blog.db"

# ─── Database Setup ────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (post_id) REFERENCES posts(id)
        );
    """)
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ─── Auth Helpers ──────────────────────────────────────────────────────────────

def get_user_from_token(request):
    """Extract user_id from Authorization header (simple token: user_id:username)."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    parts = token.split(":")
    if len(parts) != 2:
        return None
    try:
        user_id = int(parts[0])
        return user_id
    except ValueError:
        return None

def require_auth(request):
    user_id = get_user_from_token(request)
    if not user_id:
        return None, jsonify({"error": "Unauthorized"}), 401
    return user_id, None, None

# ─── Auth Routes ───────────────────────────────────────────────────────────────

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hash_password(password))
        )
        conn.commit()
        row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        return jsonify({
            "message": "Registered successfully",
            "token": f"{row['id']}:{username}",
            "user_id": row["id"],
            "username": username
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already taken"}), 409
    finally:
        conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    conn = get_db()
    row = conn.execute(
        "SELECT id, username FROM users WHERE username = ? AND password = ?",
        (username, hash_password(password))
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Invalid username or password"}), 401

    return jsonify({
        "message": "Logged in successfully",
        "token": f"{row['id']}:{row['username']}",
        "user_id": row["id"],
        "username": row["username"]
    }), 200

# ─── Post Routes ───────────────────────────────────────────────────────────────

@app.route("/posts", methods=["GET"])
def get_posts():
    conn = get_db()
    rows = conn.execute("""
        SELECT p.id, p.title, p.content, p.created_at,
               u.id AS user_id, u.username,
               COUNT(c.id) AS comment_count
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN comments c ON c.post_id = p.id
        GROUP BY p.id
        ORDER BY p.created_at DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200

@app.route("/posts", methods=["POST"])
def create_post():
    user_id, err_resp, err_code = require_auth(request)
    if err_resp:
        return err_resp, err_code

    data = request.get_json()
    title = (data.get("title") or "").strip()
    content = (data.get("content") or "").strip()

    if not title or not content:
        return jsonify({"error": "Title and content are required"}), 400

    created_at = datetime.utcnow().isoformat()
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO posts (title, content, user_id, created_at) VALUES (?, ?, ?, ?)",
        (title, content, user_id, created_at)
    )
    conn.commit()
    post_id = cur.lastrowid
    row = conn.execute("""
        SELECT p.id, p.title, p.content, p.created_at,
               u.id AS user_id, u.username
        FROM posts p JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    """, (post_id,)).fetchone()
    conn.close()
    return jsonify(dict(row)), 201

@app.route("/posts/<int:post_id>", methods=["PUT"])
def update_post(post_id):
    user_id, err_resp, err_code = require_auth(request)
    if err_resp:
        return err_resp, err_code

    conn = get_db()
    post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        conn.close()
        return jsonify({"error": "Post not found"}), 404
    if post["user_id"] != user_id:
        conn.close()
        return jsonify({"error": "You can only edit your own posts"}), 403

    data = request.get_json()
    title = (data.get("title") or "").strip()
    content = (data.get("content") or "").strip()

    if not title or not content:
        conn.close()
        return jsonify({"error": "Title and content are required"}), 400

    conn.execute(
        "UPDATE posts SET title = ?, content = ? WHERE id = ?",
        (title, content, post_id)
    )
    conn.commit()
    row = conn.execute("""
        SELECT p.id, p.title, p.content, p.created_at,
               u.id AS user_id, u.username
        FROM posts p JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    """, (post_id,)).fetchone()
    conn.close()
    return jsonify(dict(row)), 200

@app.route("/posts/<int:post_id>", methods=["DELETE"])
def delete_post(post_id):
    user_id, err_resp, err_code = require_auth(request)
    if err_resp:
        return err_resp, err_code

    conn = get_db()
    post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        conn.close()
        return jsonify({"error": "Post not found"}), 404
    if post["user_id"] != user_id:
        conn.close()
        return jsonify({"error": "You can only delete your own posts"}), 403

    conn.execute("DELETE FROM comments WHERE post_id = ?", (post_id,))
    conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Post deleted"}), 200

# ─── Comment Routes ────────────────────────────────────────────────────────────

@app.route("/comments/<int:post_id>", methods=["GET"])
def get_comments(post_id):
    conn = get_db()
    rows = conn.execute("""
        SELECT c.id, c.text, c.created_at,
               u.id AS user_id, u.username
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.post_id = ?
        ORDER BY c.created_at ASC
    """, (post_id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200

@app.route("/comments", methods=["POST"])
def create_comment():
    user_id, err_resp, err_code = require_auth(request)
    if err_resp:
        return err_resp, err_code

    data = request.get_json()
    text = (data.get("text") or "").strip()
    post_id = data.get("post_id")

    if not text:
        return jsonify({"error": "Comment text is required"}), 400
    if not post_id:
        return jsonify({"error": "post_id is required"}), 400

    conn = get_db()
    post = conn.execute("SELECT id FROM posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        conn.close()
        return jsonify({"error": "Post not found"}), 404

    created_at = datetime.utcnow().isoformat()
    cur = conn.execute(
        "INSERT INTO comments (text, user_id, post_id, created_at) VALUES (?, ?, ?, ?)",
        (text, user_id, post_id, created_at)
    )
    conn.commit()
    comment_id = cur.lastrowid
    row = conn.execute("""
        SELECT c.id, c.text, c.created_at,
               u.id AS user_id, u.username
        FROM comments c JOIN users u ON c.user_id = u.id
        WHERE c.id = ?
    """, (comment_id,)).fetchone()
    conn.close()
    return jsonify(dict(row)), 201

@app.route("/comments/<int:comment_id>", methods=["DELETE"])
def delete_comment(comment_id):
    user_id, err_resp, err_code = require_auth(request)
    if err_resp:
        return err_resp, err_code

    conn = get_db()
    comment = conn.execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()
    if not comment:
        conn.close()
        return jsonify({"error": "Comment not found"}), 404
    if comment["user_id"] != user_id:
        conn.close()
        return jsonify({"error": "You can only delete your own comments"}), 403

    conn.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Comment deleted"}), 200

# ─── Run ───────────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    return "Backend is running 🚀"

@app.route('/test')
def test():
    return "Test working"

if __name__ == "__main__":
    init_db()
    print("✦ Blog API running at http://127.0.0.1:5000")
    app.run(debug=True)
