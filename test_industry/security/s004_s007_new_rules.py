"""行业标准测试 S004-S007 新规则"""
import os
import xml.etree.ElementTree as ET
import xml.dom.minidom
import hashlib
import requests
from urllib.request import urlopen, Request

# ========== S004: 路径遍历 (CWE-22) ==========
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

def path_traversal_zip(filename, zip_path):
    import zipfile
    zipfile.ZipFile(zip_path).extract(filename, "/tmp")

def path_traversal_tar(filename, tar_path):
    import tarfile
    tarfile.open(tar_path).extract(filename, "/tmp")

def safe_path_basename(filename):
    safe = os.path.basename(filename)
    open(os.path.join("/safe/dir", safe)).read()

def safe_path_constant():
    open("/safe/dir/file.txt").read()

def safe_path_no_user_input():
    path = os.path.join("/var", "log", "app.log")
    open(path).read()

# ========== S005: SSRF (CWE-918) ==========
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
    from urllib.request import urlretrieve
    urlretrieve(url, "/tmp/file")

def safe_requests_constant():
    requests.get("https://api.example.com/v1/")

def safe_urlopen_constant():
    urlopen("https://api.example.com/")

# ========== S006: 弱加密 (CWE-327) ==========
def weak_md5(data):
    return hashlib.md5(data.encode()).hexdigest()

def weak_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()

def weak_md5_bytes(data):
    return hashlib.md5(data).hexdigest()

def weak_sha1_bytes(data):
    return hashlib.sha1(data).hexdigest()

def safe_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def safe_sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def safe_sha3_256(data):
    return hashlib.sha3_256(data.encode()).hexdigest()

# ========== S007: XXE (CWE-611) ==========
def xxe_lxml(xml_input):
    import lxml.etree
    root = lxml.etree.fromstring(xml_input)
    return root.findtext("name")

def xxe_minidom(xml_input):
    doc = xml.dom.minidom.parseString(xml_input)
    return doc.getElementsByTagName("name")[0].firstChild.data

def xxe_etree_parse(xml_file):
    tree = ET.parse(xml_file)
    return tree.getroot()

def xxe_minidom_parse(xml_file):
    doc = xml.dom.minidom.parse(xml_file)
    return doc.documentElement

def safe_etree_fromstring(xml_input):
    root = ET.fromstring(xml_input)
    return root.findtext("name")
