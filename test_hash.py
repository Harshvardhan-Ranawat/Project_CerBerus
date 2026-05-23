import time
import os
import shutil
import hashlib

def run_test():
    os.makedirs("test_env", exist_ok=True)
    with open("test_env/passwords.txt", "w") as f:
        f.write("Admin Password: P@ssw0rd\n")

    def get_file_hash(path):
        try:
            with open(path, "rb") as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            return str(e)

    orig_hash = get_file_hash("test_env/passwords.txt")
    print("Original hash:", orig_hash)
    
    # Simulate a copy
    shutil.copy("test_env/passwords.txt", "test_env/copied_passwords.txt")
    copied_hash = get_file_hash("test_env/copied_passwords.txt")
    print("Copied hash:", copied_hash)

if __name__ == "__main__":
    run_test()
