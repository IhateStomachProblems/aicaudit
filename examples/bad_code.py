import sqlite3, os, subprocess

def bad_query(conn, user_id):
    # SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn.execute(query)

    # This is fine (parameterized)
    conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))

def dangerous_stuff():
    api_key = "sk-abc123def456ghi789jkl012"
    password = "super_secret_12345"
    exec("print('hello')")
    eval("1+1")
    os.system("ls")
    subprocess.run(["rm", "-rf", "/"], shell=True)
