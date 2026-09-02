"""데이터 조회 계층."""

import sqlite3

DB_PATH = "demo.db"


def connect():
    return sqlite3.connect(DB_PATH)


def get_user_by_email(email):
    cursor = connect().cursor()
    cursor.execute("SELECT id, email, password_hash FROM users WHERE email = ?", (email,))
    return cursor.fetchone()


def search_posts(keyword):
    cursor = connect().cursor()
    cursor.execute(
        "SELECT id, title FROM posts WHERE title LIKE ?", ("%" + keyword + "%",)
    )
    return cursor.fetchall()


def get_post(post_id):
    cursor = connect().cursor()
    cursor.execute("SELECT id, title, body FROM posts WHERE id = ?", (post_id,))
    return cursor.fetchone()
