"""Benchmark corpus: S004 path traversal, S005 SSRF, S006 weak crypto, S007 XXE."""
import hashlib
import os
import xml.dom.minidom
import xml.etree.ElementTree as ET
from urllib.request import Request, urlopen, urlretrieve

import requests

# ========== S004 path traversal: positives ==========
def path_traversal_join(filename):
    path = os.path.join("/var/www/uploads", filename)
    open(path).read()

def path_traversal_concat(filename):
    open("/var/www/uploads/" + filename).read()

def path_traversal_fstring(filename):
    open(f"/var/www/uploads/{filename}").read()

def path_traversal_abspath(filename):
    open(os.path.abspath(os.path.join("/var/www/uploads", filename))).read()

def path_traversal_normpath(filename):
    open(os.path.normpath(os.path.join("/var/www/uploads", filename))).read()

def path_traversal_realpath(filename):
    open(os.path.realpath(os.path.join("/var/www/uploads", filename))).read()

# ========== S004: negatives ==========
def safe_path_basename(filename):
    open(os.path.join("/safe/dir", os.path.basename(filename))).read()

def safe_path_constant():
    open("/safe/dir/file.txt").read()

def safe_path_base_dir():
    # provably constant: pure folds of __file__ and literals
    base = os.path.dirname(os.path.abspath(__file__))
    open(os.path.join(base, "config.json")).read()

# ========== S005 SSRF: positives ==========
def ssrf_requests(url):
    requests.get(url)

def ssrf_requests_post(url, data):
    requests.post(url, data=data)

def ssrf_requests_put(url):
    requests.put(url)

def ssrf_requests_delete(url):
    requests.delete(url)

def ssrf_urlopen_simple(url):
    urlopen(url)

def ssrf_urlopen_request(url):
    req = Request(url)
    urlopen(req)

def ssrf_urllib_urlretrieve(url):
    urlretrieve(url, "/tmp/file")

def ssrf_environ_target():
    import os
    target = os.environ["HEALTHCHECK_URL"]
    requests.get(target)

# ========== S005: negatives ==========
def safe_requests_constant():
    requests.get("https://api.example.com/v1/")

def safe_requests_constant_var():
    endpoint = "https://api.example.com/v2/status"
    requests.get(endpoint)

# ========== S006 weak crypto: positives ==========
def weak_md5(data):
    return hashlib.md5(data.encode()).hexdigest()

def weak_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()

# ========== S006: negatives ==========
def safe_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

# ========== S007 XXE: positives ==========
def xxe_lxml_str(xml_input):
    import lxml.etree
    lxml.etree.fromstring(xml_input)

def xxe_minidom(xml_input):
    xml.dom.minidom.parseString(xml_input)

def xxe_etree_parse(xml_file):
    ET.parse(xml_file)  # import alias

def xxe_minidom_parse(xml_file):
    xml.dom.minidom.parse(xml_file)

def xxe_elementtree_parse(xml_file):
    import xml.etree.ElementTree as ElementTree
    ElementTree.parse(xml_file)  # alias

# ========== S007: conservative / negatives ==========
def conservative_etree_fromstring(xml_input):
    # Python 3.8+ ET.fromstring does not expand external entities; the rule
    # keeps a conservative flag for internal-entity risks (documented FP).
    ET.fromstring(xml_input)

def safe_defusedxml():
    from defusedxml import ElementTree
    ElementTree.parse("safe.xml")
