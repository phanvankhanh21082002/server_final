import subprocess
import json
import sys

def scan_file_with_clamav(file_path):
    try:
        result = subprocess.run(['clamscan', file_path], capture_output=True, text=True)
        scan_summary = result.stdout
        if result.returncode in [0, 1]:  # 0 = OK, 1 = Found virus
            return {'filename': file_path, 'details': scan_summary}
        else:
            print(f"Error running clamscan: {result.stderr}")
            return None
    except subprocess.CalledProcessError as e:
        print(f"Error running clamscan: {e}")
        return None

def main():
    file_path = sys.argv[1]
    
    scan_results = scan_file_with_clamav(file_path)
    if scan_results is not None:
        print(json.dumps(scan_results))
    else:
        print("Failed to scan the file or no results found.")

if __name__ == "__main__":
    main()
