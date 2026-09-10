"""Benchmark corpus: constant / safe usage — everything here must stay clean.

Constant dangerous calls are deliberately not flagged by aicaudit's taint mode
(provably no injection path). Bandit flags most of them; this is the
documented, intentional design difference the benchmark reports honestly.
"""
import io
import os
import pickle
import subprocess
import xml.etree.ElementTree as ET
import yaml

def constant_eval():
    x = eval("1+1")
    return x

def constant_exec():
    exec("x = 1")

def constant_pickle_roundtrip():
    # constant bytes: no injection path, stays silent in taint mode
    return pickle.loads(b"constant-bytes-literal")

def constant_yaml_harness():
    return yaml.load("key: value", Loader=yaml.SafeLoader)

def constant_os_system():
    os.system("ls")

def constant_subprocess():
    subprocess.run(["ls", "-la"], shell=False, capture_output=True)

def safe_yaml_safe_load():
    return yaml.safe_load("key: value")

def safe_pickle_dumps():
    return pickle.dumps({"a": 1})

def safe_etree_constant():
    ET.parse("config.xml")

def normal_calls():
    print("safe")
    return len([1, 2, 3])
