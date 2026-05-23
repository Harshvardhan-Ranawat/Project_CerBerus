import subprocess
import time

print("Starting main.py to create dummy files...")
p = subprocess.Popen(["python", "main.py"], stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
time.sleep(5)
p.kill()
stdout, stderr = p.communicate()
print("STDOUT:")
print(stdout)
if stderr:
    print("STDERR:")
    print(stderr)
print("Done.")
