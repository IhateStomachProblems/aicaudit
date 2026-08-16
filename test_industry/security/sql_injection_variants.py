"""行业标准 CWE-89 SQL Injection 测试"""
import sqlite3

# ========== 真阳性 ==========
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

# ========== 真阴性 ==========
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
