import sys
import subprocess
import concurrent.futures
import os
import threading
import shutil
import glob
import hashlib

def run_script(script, *args):
    try:
        result = subprocess.run(['python3', script, *args], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running {script}: {result.stderr}")
        return result
    except Exception as e:
        print(f"Exception running {script}: {e}")
        return None

def run_clamscan(file_path, output_file):
    try:
        with open(output_file, 'w') as output:
            result = subprocess.run(['clamscan', file_path], stdout=output, stderr=subprocess.PIPE, text=True)
        return result.returncode
    except Exception as e:
        print(f"Exception running clamscan: {e}")
        return None

def is_file_clean(clamav_output_file):
    try:
        with open(clamav_output_file, 'r') as file:
            for line in file:
                if "Infected files:" in line:
                    parts = line.split(":")
                    infected_files = int(parts[1].strip())
                    print(f"Debug: Infected files: {infected_files}")  # Debugging line
                    return infected_files == 0
        return False
    except FileNotFoundError:
        print(f"File not found: {clamav_output_file}")
        return False
    except Exception as e:
        print(f"Exception reading file: {e}")
        return False

def update_report(file_hash, result_text):
    txt_file_path = os.path.join("/var/www/html/reports_txt", f"{file_hash}.txt")

    try:
        # Write the final result to txt file
        with open(txt_file_path, 'w') as f:
            f.write(result_text)

        print(f"Report updated at {txt_file_path}")
    except Exception as e:
        print(f"Exception updating report: {e}")

def list_apk_files(root_dir):
    apk_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith('.apk'):
                apk_files.append(os.path.join(dirpath, filename))
    return apk_files

def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    return sha256_hash.hexdigest()

def main():
    root_dir = '../apk_analysis'
    ml_script = "../code_static/machine_learning_ccn.py"
    apk_files = list_apk_files(root_dir)

    for apk_file_path in apk_files:
        extract_folder = os.path.dirname(apk_file_path)
        file_hash = calculate_file_hash(apk_file_path)

        if not file_hash:
            continue

        clamav_output_file = os.path.join(extract_folder, f"{file_hash}_clamav.txt")

        # Initialize variables to capture script outputs
        clamav_clean = False
        ml_is_malware = False

        # Use threading events to synchronize the completion of the scripts
        event_clamav_done = threading.Event()
        event_ml_done = threading.Event()

        def run_clamav_script():
            nonlocal clamav_clean
            try:
                clamscan_result = run_clamscan(apk_file_path, clamav_output_file)
                print(f"ClamAV Output saved to {clamav_output_file}")  # Debugging line
                clamav_clean = is_file_clean(clamav_output_file)
                event_clamav_done.set()
            except Exception as e:
                print(f"Exception running clamscan: {e}")
                event_clamav_done.set()

        def run_ml_script():
            nonlocal ml_is_malware
            try:
                ml_result = run_script(ml_script, apk_file_path)
                if ml_result and ml_result.returncode == 0:
                    print(f"ML Output for {apk_file_path}: {ml_result.stdout}")
                    ml_is_malware = "malware" in ml_result.stdout.strip().lower()
                    event_ml_done.set()
                else:
                    print(f"machine_learning_ccn.py failed for {apk_file_path}")
                    event_ml_done.set()
            except Exception as e:
                print(f"Exception running machine_learning_ccn.py: {e}")
                event_ml_done.set()

        # Run the scripts in separate threads
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.submit(run_clamav_script)
            executor.submit(run_ml_script)

        # Wait for all scripts to complete
        event_clamav_done.wait()
        event_ml_done.wait()

        # Determine final result based on clamav and ml results
        if clamav_clean:
            final_result = "Clean"
        elif not clamav_clean and ml_is_malware:
            final_result = "Malware"
        else:
            final_result = "Warning"

        try:
            # Update the reports with the new result
            update_report(file_hash, f"Result: {final_result}")
        except Exception as e:
            print(f"Exception in updating report: {e}")

        print(f"All scripts have finished for {apk_file_path}")

if __name__ == "__main__":
    main()
