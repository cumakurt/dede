"""Static-analysis fixtures only; never imported or executed."""

import os
import subprocess

import requests
from flask import request


def unsafe_sql(cursor):
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    # ruleid: dede.python.taint.sql-injection
    cursor.execute(query)


def safe_sql(cursor):
    name = request.args.get("name")
    # ok: dede.python.taint.sql-injection
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))


def unsafe_shell():
    command = request.form.get("command")
    # ruleid: dede.python.taint.command-injection
    os.system(command)


def safe_shell():
    argument = request.form.get("argument")
    # ok: dede.python.taint.command-injection
    subprocess.run(["echo", argument], shell=False, check=True)


def unsafe_path():
    name = request.args["file"]
    path = "/uploads/" + name
    # ruleid: dede.python.taint.path-traversal
    return open(path)


def safe_path():
    # ok: dede.python.taint.path-traversal
    return open("/uploads/constant.txt")


def unsafe_request():
    url = request.args.get("url")
    # ruleid: dede.python.taint.ssrf
    return requests.get(url, timeout=5)


def safe_request():
    query = request.args.get("query")
    # ok: dede.python.taint.ssrf
    return requests.get("https://example.invalid/search", params={"q": query}, timeout=5)
