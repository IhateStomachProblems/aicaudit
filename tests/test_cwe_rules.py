"""Tests for new CWE rules (S004-S007) and S002/S003 expansions."""
import ast
from pathlib import Path

from codeaudit.rules.base import ScanContext
from codeaudit.rules.security.dangerous_functions import DangerousFunctions
from codeaudit.rules.security.path_traversal import PathTraversal
from codeaudit.rules.security.secret_leak import SecretLeak
from codeaudit.rules.security.ssrf import SSRF
from codeaudit.rules.security.weak_crypto import WeakCrypto
from codeaudit.rules.security.xml_xxe import XXE


def make_context(code):
    tree = ast.parse(code)
    lines = code.splitlines(keepends=False)
    return tree, ScanContext(file_path=Path("fake.py"), source=code, lines=lines)


# ---------- S004 Path traversal ----------
def test_path_traversal_detected():
    code = 'data = open(get_input(), "r")'
    tree, ctx = make_context(code)
    findings = PathTraversal().check(tree, ctx)
    assert len(findings) == 1


def test_path_traversal_literal_safe():
    code = 'data = open("config.json", "r")'
    tree, ctx = make_context(code)
    findings = PathTraversal().check(tree, ctx)
    assert len(findings) == 0


# ---------- S005 SSRF ----------
def test_ssrf_detected():
    code = "resp = requests.get(get_user_url())"
    tree, ctx = make_context(code)
    findings = SSRF().check(tree, ctx)
    assert len(findings) == 1


def test_ssrf_literal_safe():
    code = 'resp = requests.get("https://example.com")'
    tree, ctx = make_context(code)
    findings = SSRF().check(tree, ctx)
    assert len(findings) == 0


# ---------- S006 Weak crypto ----------
def test_weak_md5_detected():
    code = "h = hashlib.md5(data)"
    tree, ctx = make_context(code)
    findings = WeakCrypto().check(tree, ctx)
    assert len(findings) == 1


def test_weak_des_detected():
    code = "cipher = DES.new(key, DES.MODE_ECB)"
    tree, ctx = make_context(code)
    findings = WeakCrypto().check(tree, ctx)
    assert len(findings) >= 1


# ---------- S007 XXE ----------
def test_xxe_etree_detected():
    code = "tree = etree.parse(xml_file)"
    tree, ctx = make_context(code)
    findings = XXE().check(tree, ctx)
    assert len(findings) == 1


def test_xxe_secure_ok():
    code = "tree = etree.fromstring(data, parser=etree.XMLParser(resolve_entities=False))"
    tree, ctx = make_context(code)
    findings = XXE().check(tree, ctx)
    assert len(findings) == 0


# ---------- S003 expansion ----------
def test_s003_marshal_detected():
    code = "data = marshal.loads(payload)"
    tree, ctx = make_context(code)
    findings = DangerousFunctions().check(tree, ctx)
    assert any("marshal" in f.message for f in findings)


def test_s003_os_popen_detected():
    code = "out = os.popen('ls')"
    tree, ctx = make_context(code)
    findings = DangerousFunctions().check(tree, ctx)
    assert any("os.popen" in f.message for f in findings)


def test_s003_ctypes_detected():
    code = "lib = ctypes.CDLL('libc.so')"
    tree, ctx = make_context(code)
    findings = DangerousFunctions().check(tree, ctx)
    assert any("ctypes" in f.message for f in findings)


def test_s003_shelve_detected():
    code = "d = shelve.open('db.shelve')"
    tree, ctx = make_context(code)
    findings = DangerousFunctions().check(tree, ctx)
    assert any("shelve" in f.message for f in findings)


def test_s003_subprocess_getoutput():
    code = "out = subprocess.getoutput('ls')"
    tree, ctx = make_context(code)
    findings = DangerousFunctions().check(tree, ctx)
    assert any("getoutput" in f.message for f in findings)


# ---------- S002 expansion ----------
def test_s002_aws_access_key():
    code = 'aws_access_key = "AKIAIOSFODNN7EXAMPLE"'
    tree, ctx = make_context(code)
    findings = SecretLeak().check(tree, ctx)
    assert len(findings) == 1


def test_s002_ssh_private_key():
    code = 'private_key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA\\n-----END RSA PRIVATE KEY-----"'
    tree, ctx = make_context(code)
    findings = SecretLeak().check(tree, ctx)
    assert len(findings) == 1


def test_s002_db_url():
    code = 'db_url = "postgresql://admin:secretpass@localhost:5432/mydb"'
    tree, ctx = make_context(code)
    findings = SecretLeak().check(tree, ctx)
    assert len(findings) == 1


def test_s002_jwt():
    code = 'token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123def456ghi789"'
    tree, ctx = make_context(code)
    findings = SecretLeak().check(tree, ctx)
    assert len(findings) == 1
