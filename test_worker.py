import threading
import time
import os
import shutil

class MockEvent:
    def __init__(self, path):
        self.src_path = path

copied_candidates = []
ORIGINAL_HASH = "faf98c8cd30dc88c65dd34b5d45e7373"

def on_created(event):
    if "passwords.txt" in event.src_path:
        print(f"Added to candidates: {event.src_path}")
        copied_candidates.append((event.src_path, time.time()))

def get_file_hash(path):
    print(f"Hashing {path} ...")
    return ORIGINAL_HASH

def log_event(action, path):
    print(f"LOG: {action} {path}")

def process_copy_events():
    print("Process started.")
    while True:
        time.sleep(2)
        print(f"Tick... candidates: {copied_candidates}")
        for item in copied_candidates[:]:
            path, t = item
            diff = time.time() - t
            print(f"Checking {path}, diff={diff}")
            if diff > 2:
                copied_hash = get_file_hash(path)
                print(f"Hash: {copied_hash}")
                if copied_hash == ORIGINAL_HASH:
                    log_event("COPIED", path)
                copied_candidates.remove(item)

t = threading.Thread(target=process_copy_events, daemon=True)
t.start()

time.sleep(1)
on_created(MockEvent("E:\\passwords.txt"))
time.sleep(5)
