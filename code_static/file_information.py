import os
import hashlib
import json
import sys
from apkutils import APK

def get_file_info(apk_path):
    file_info = {}
    
    # File name and size
    file_info['File Name'] = os.path.basename(apk_path)
    file_info['Size'] = f"{os.path.getsize(apk_path) / (1024 * 1024):.2f}MB"
    
    # Calculate hashes
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    
    with open(apk_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
            hash_sha1.update(chunk)
            hash_sha256.update(chunk)
    
    file_info['MD5'] = hash_md5.hexdigest()
    file_info['SHA1'] = hash_sha1.hexdigest()
    file_info['SHA256'] = hash_sha256.hexdigest()
    
    return file_info

def print_file_info(file_info):
    print("FILE INFORMATION")
    print("-" * 80)
    for key, value in file_info.items():
        print(f"{key}: {value}")

def main():
    apk_path = sys.argv[1]
    file_info = get_file_info(apk_path)
    print(json.dumps(file_info))

if __name__ == "__main__":
    main()
