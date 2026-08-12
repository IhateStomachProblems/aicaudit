import os
proj_dir = r"C:\Users\17390\Desktop\开源git项目\codeaudit"

content = '''"""This is a bad file with many issues for testing."""

import sqlite3
import os

API_KEY = "sk-1234567890abcdefghijklmnop"
password = "super_secret_password_123"
username = "admin"


def save_user(conn, user_id):
    # SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn.execute(query)


def process_data(items, options=None):
    # Bare except and complex logic
    try:
        result = []
        for item in items:
            if item.get("active"):
                if item.get("price") > 100:
                    if item.get("stock") > 0:
                        if options and options.get("discount"):
                            result.append(item["price"] * 0.9)
                        else:
                            result.append(item["price"])
                else:
                    result.append(item["price"])
    except:
        pass

    magic = 1729
    result2 = []  # unused local
    return result, magic  # TODO: remove unused variable later


def dangerous():
    exec("print('hello')")
    eval("1+1")
    os.system("ls")
'''

with open(os.path.join(proj_dir, "examples", "bad_code2.py"), "w", encoding="utf-8") as f:
    f.write(content)
print("example rewritten")
