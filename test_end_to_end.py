import sys
import subprocess
import time
import os
import shutil

log_file = "logs/alerts.log"
if os.path.exists(log_file):
    os.remove(log_file)

p = subprocess.Popen([sys.executable, "-u", "main.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(3)

print("Copying inside HONEY_DIR...")
shutil.copy("honeyfiles/passwords.txt", "honeyfiles/copied_passwords.txt")

time.sleep(5)
p.kill()
out, err = p.communicate()
print("STDOUT:")
print(out)
print("STDERR:")
print(err)

print("Log content:")
if os.path.exists(log_file):
    with open(log_file, "r") as f:
        print(f.read())
else:
    print("NO LOG FILE GENERATED.")
