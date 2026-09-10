"""Benchmark corpus: CWE-89 SQL injection.

Function-level labeled samples. Positive cases are dynamic (parameter-driven),
so they exercise the taint engine's UNKNOWN/TAINTED tiers; negatives are
parameterized or literal queries.
"""
import sqlite3

# ========== positives ==========
def sqlite3_fstring(conn, uid):
    q = f"SELECT * FROM users WHERE id = {uid}"
    conn.execute(q)

def sqlite3_concat(conn, uid):
    conn.execute("SELECT * FROM users WHERE id = '" + uid + "'")

def sqlite3_percent_format(conn, uid):
    conn.execute("SELECT * FROM users WHERE id = %s" % uid)

def sqlite3_dot_format(conn, uid):
    conn.execute("SELECT * FROM users WHERE id = {}".format(uid))

def sqlite3_joined_with_variable(conn, uid, name):
    q = "SELECT * FROM " + name + " WHERE id = " + uid
    conn.execute(q)

def sqlite3_executemany(conn, uid):
    conn.executemany("DELETE FROM users WHERE id = " + uid, [])

def sqlite3_executescript_ignore(conn, uid):
    conn.executescript("DROP TABLE users WHERE id = " + uid)

def sqlite3_multiline_fstring(conn, uid):
    q = ("SELECT * FROM users " f"WHERE id = {uid} " "AND active = 1")
    conn.execute(q)

def sqlite3_nested_var(conn, uid):
    q2 = "SELECT * FROM users WHERE id = " + uid
    conn.execute(q2)

def sqlite3_join_list(conn, parts):
    q = " ".join(["SELECT * FROM users WHERE id =", parts[0]])
    conn.execute(q)

def sqlite3_flask_request(conn):
    # end-to-end taint: source -> sink with a complete path
    from flask import request
    uid = request.args.get("id")
    conn.execute(f"SELECT * FROM users WHERE id = {uid}")

# ========== negatives ==========
def sqlite3_param_q(conn, uid):
    conn.execute("SELECT * FROM users WHERE id = ?", (uid,))

def sqlite3_param_named(conn, uid):
    conn.execute("SELECT * FROM users WHERE id = :uid", {"uid": uid})

def sqlite3_param_list(conn, uid):
    conn.execute("SELECT * FROM users WHERE id = ?", [uid])

def sqlite3_literal_no_input(conn):
    conn.execute("SELECT 1")
    conn.execute("SELECT * FROM users WHERE id = 42")

def sqlite3_literal_param_combo(conn, uid):
    conn.execute("SELECT * FROM users WHERE id = ? AND active = 1", (uid,))

def sqlite3_constant_variable(conn):
    # provably-constant SQL variable: the taint engine proves it safe
    query = "SELECT name FROM config LIMIT 1"
    conn.execute(query)
