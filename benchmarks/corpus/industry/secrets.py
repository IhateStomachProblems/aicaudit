"""Benchmark corpus: CWE-798 hardcoded secrets.

All strings below are well-known documentation placeholders
(AWS docs example keys, fake token shapes) — no real credentials.
"""
import os

# ========== positives (module-level assignments) ==========
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"
gh_oauth = "gho_1234567890abcdefghijklmnopqrstuvwxyzAB"
secret_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
api_token = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
DB_URL = "postgresql://user:password123@localhost:5432/db"
ssh_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA"
redis_url_nouser = "redis://:password123@localhost:6379/0"

# ========== negatives ==========
def safe_from_env():
    return os.environ.get("DATABASE_URL")

def safe_short_name():
    tiny_key = "abc"
    return tiny_key

def safe_normal_var():
    count = 42
    name = "hello world"
    return count, name

def safe_non_secret_long():
    description = "this is a long description string that is not a secret"
    return description
