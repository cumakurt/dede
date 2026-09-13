"""
Intentionally vulnerable Python samples for Dede tests.
All secrets below are FAKE / EXAMPLE values only — not real credentials.
"""

import os
import sqlite3


def run_command(user_input: str) -> None:
    # FAKE vulnerability: command injection
    os.system(user_input)


def unsafe_query(username: str) -> None:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    # FAKE vulnerability: SQL injection via format string
    cur.execute("SELECT * FROM users WHERE name = '%s'" % username)


def hardcoded_secret() -> str:
    # FAKE secret for gitleaks detection — NOT A REAL KEY
    aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    password = "FAKE_PASSWORD_DO_NOT_USE"
    return aws_secret_access_key + password


def dangerous_eval(expr: str):
    return eval(expr)
