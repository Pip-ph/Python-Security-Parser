import os
import subprocess

#1. os.system check
os.system("rm -rf /")

#2. subprocess with shell=True check
subprocess.run("ls -la", shell=True)
subprocess.call("echo hello", shell=True)

#3. eval check
eval("1 + 1")

#4. exec check
exec("import sys; print(sys.version)")