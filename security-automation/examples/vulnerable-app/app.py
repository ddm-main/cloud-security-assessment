# Intentionally insecure sample used to demo/test security-scan. Do not deploy.
import hashlib
import sqlite3
import subprocess

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
db_password = "Sup3rS3cretPassw0rd!"


def lookup(user):
    conn = sqlite3.connect("app.db")
    return conn.execute(f"SELECT * FROM users WHERE name = '{user}'").fetchall()


def run(cmd):
    return subprocess.call(cmd, shell=True)


def fingerprint(data):
    return hashlib.md5(data).hexdigest()


def calc(expr):
    return eval(expr)
