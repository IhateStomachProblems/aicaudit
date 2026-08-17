"""行业标准测试 S004-S007"""
import os
import xml.etree.ElementTree as ET
import xml.dom.minidom
import hashlib
import requests
from urllib.request import urlopen, Request

# ========== S004 ==========
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
def safe_path_basename(filename):
    open(os.path.join("/safe/dir", os.path.basename(filename))).read()
def safe_path_constant():
    open("/safe/dir/file.txt").read()

# ========== S005 ==========
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

# ========== S006 ==========
def weak_md5(data):
    return hashlib.md5(data.encode()).hexdigest()
def weak_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()
def safe_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

# ========== S007 ==========
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
    ElementTree.parse(xml_file)  # 别名
def safe_etree_fromstring(xml_input):
    ET.fromstring(xml_input)
def safe_defusedxml():
    from defusedxml import ElementTree
    ElementTree.parse("safe.xml")
