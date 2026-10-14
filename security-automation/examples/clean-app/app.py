import os
import sqlite3


def lookup(user):
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users WHERE name = ?", (user,)).fetchall()


API_TOKEN = os.environ["API_TOKEN"]
