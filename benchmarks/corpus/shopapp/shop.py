"""Benchmark corpus: shopapp — a small realistic Flask app with planted bugs.

Each planted vulnerability maps to an expected aicaudit rule in
benchmarks/ground_truth.json. The app is deliberately tiny but idiomatic:
routes, a db helper, an xml import, a webhook, an admin report.
"""
import hashlib
import os
import random
import sqlite3
import xml.etree.ElementTree as ET

import requests
from flask import Flask, request, send_file

# S002: hardcoded secrets (documentation placeholders, not real)
SECRET_KEY = "sk-shopapp-6f2a4c8e1d9b7a3f5e0c2d4b6a8f1e3d"
DATABASE_URL = "postgresql://admin:S3cretPass@db.internal:5432/shop"

app = Flask(__name__)

DB = sqlite3.connect("shop.db")


# ── clean helpers ───────────────────────────────────────────────────────────

def get_product_safe(product_id):
    row = DB.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    return row.fetchone()


def load_config_safe():
    base = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base, "config.json"), encoding="utf-8") as fh:
        return fh.read()


def ping_internal_health():
    # constant URL, no user input — must stay clean
    return requests.get("https://health.internal.example.com/ping", timeout=5)


# ── planted vulnerabilities ─────────────────────────────────────────────────

@app.route("/search")
def search_products():
    # S001: f-string SQL with request input (full taint path)
    term = request.args.get("q", "")
    rows = DB.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return {"rows": rows.fetchall()}


@app.route("/orders")
def list_orders():
    # S001: %-format SQL with request input
    user = request.args.get("user")
    return DB.execute("SELECT * FROM orders WHERE user = '%s'" % user).fetchall()


def _sort_column_from_request():
    return request.args.get("sort", "id")


@app.route("/products")
def products_sorted():
    # S001 + interprocedural: taint returns from helper into the sink
    col = _sort_column_from_request()
    return DB.execute(f"SELECT * FROM products ORDER BY {col}").fetchall()


@app.route("/download")
def download_file():
    # S004: path traversal — user input straight into open()
    name = request.args.get("name")
    with open(f"/var/shop/files/{name}", "rb") as fh:
        return send_file(fh)


@app.route("/avatar/<path>")
def user_avatar(path):
    # S004: os.path.join with user input
    full = os.path.join("/var/shop/avatars", path)
    return send_file(full)


@app.route("/webhook/fetch")
def fetch_webhook():
    # S005: SSRF — user-controlled URL
    target = request.args.get("url")
    return requests.get(target).text


def _hash_password(password):
    # S006: MD5 for passwords
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/import/products")
def import_products():
    # S007: XXE — user-supplied XML into ElementTree.parse
    uploaded = request.files.get("catalog")
    tree = ET.parse(uploaded)
    return {"imported": len(tree.getroot())}


def _make_session_token(user_id):
    # S008: insecure randomness for session tokens
    return f"{user_id}-{random.randint(100000, 999999)}"


@app.route("/admin/report")
def admin_report():
    # S003: eval of user input
    expr = request.args.get("expr")
    return {"value": eval(expr)}


@app.route("/admin/ping")
def admin_ping():
    # S003: os.system with user input
    host = request.args.get("host")
    return os.popen(f"ping -c1 {host}").read()


if __name__ == "__main__":
    app.run(debug=True)
