"""Benchmark corpus: S003 dangerous functions — dynamic-argument positives.

Design note: aicaudit's taint mode distinguishes *injection-reachable* usage
(dynamic argument, unknown/tainted origin) from *constant* usage. Constant
dangerous calls (eval("1+1")) are a code smell, not an injection risk; this
corpus tests the injection-reachable tier. See dangerous_constant.py for the
constant tier, which aicaudit intentionally does not flag in full scans.
"""
import ctypes
import io
import os
import pickle
import shelve
import subprocess
import yaml

def pos_eval_dynamic(cmd):
    eval(cmd)

def pos_exec_dynamic(code):
    exec(code)

def pos_pickle_loads(payload):
    pickle.loads(payload)

def pos_pickle_load(stream):
    pickle.load(io.BytesIO(stream))

def pos_marshal_loads(blob):
    import marshal
    marshal.loads(blob)

def pos_shelve_open(path):
    s = shelve.open(path, writeback=True)
    s.close()

def pos_yaml_load(stream):
    yaml.load(stream, Loader=yaml.Loader)

def pos_os_system(cmd):
    os.system(cmd)

def pos_os_popen(cmd):
    os.popen(cmd)

def pos_subprocess_run_shell(cmd):
    subprocess.run(cmd, shell=True)

def pos_subprocess_getoutput(cmd):
    subprocess.getoutput(cmd)

def pos_ctypes_cdll(path):
    libc = ctypes.CDLL(path)

def pos_input_usage():
    user_input = input()
    return user_input

def pos_flask_route_to_eval():
    # end-to-end: user input reaches eval through a call chain
    from flask import request
    expr = request.form.get("expr")
    eval(expr)
