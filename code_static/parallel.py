import sys
import subprocess
import concurrent.futures
import os
import threading
import shutil
import glob

def run_script(script, *args):
    try:
        result = subprocess.run(['python3', script, *args], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running {script}: {result.stderr}")
        return result
    except Exception as e:
        print(f"Exception running {script}: {e}")
        return None

def run_jadx(apk_file, output_dir):
    try:
        result = subprocess.run(['jadx', apk_file, '-d', output_dir], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running jadx: {result.stderr}")
        return result.returncode
    except Exception as e:
        print(f"Exception running jadx: {e}")
        return 1

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

def move_files_when_ready(new_dir, file_hash, result_text):
    html_file_path = os.path.join(new_dir, f"{file_hash}.html")
    txt_file_path = os.path.join(new_dir, f"{file_hash}.txt")

    # Write the final result to txt file
    with open(txt_file_path, 'w') as f:
        f.write(result_text)

    reports_txt_dir = "/var/www/html/reports_txt"
    reports_html_dir = "/var/www/html/reports_html"

    try:
        # Move the files to their respective directories
        os.makedirs(reports_txt_dir, exist_ok=True)
        os.makedirs(reports_html_dir, exist_ok=True)

        os.rename(txt_file_path, os.path.join(reports_txt_dir, f"{file_hash}.txt"))
        os.rename(html_file_path, os.path.join(reports_html_dir, f"{file_hash}.html"))

        print(f"Reports moved to {reports_txt_dir} and {reports_html_dir}")
    except Exception as e:
        print(f"Exception moving files: {e}")

def cleanup_directory(directory, keep_files):
    for item in os.listdir(directory):
        item_path = os.path.join(directory, item)
        if item_path not in keep_files:
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
            else:
                os.remove(item_path)
    print(f"Cleaned up directory {directory}, kept files: {keep_files}")

def main(apk_file_path, extract_folder, file_hash):
    report_script = "../code_static/report.py"
    report_fail_script = "../code_static/report_jadx_fail.py"
    ml_script = "../code_static/machine_learning_ccn.py"
    clamav_output_file = os.path.join(extract_folder, f"{file_hash}_clamav.txt")

    # Initialize variables to capture script outputs
    clamav_clean = False
    ml_is_malware = False

    # Get the file size in MB
    file_size_mb = os.path.getsize(apk_file_path) / (1024 * 1024)

    # Run jadx to decompile the APK
    try:
        jadx_result = run_jadx(apk_file_path, extract_folder)
    except Exception as e:
        print(f"jadx encountered an error: {e}")
        return

    if jadx_result != 0:
        print(f"jadx failed for {apk_file_path}")
        report_script = report_fail_script

    # Use threading events to synchronize the completion of the scripts
    event_report_done = threading.Event()
    event_clamav_done = threading.Event()
    event_ml_done = threading.Event()

    def run_report_script():
        try:
            report_result = run_script(report_script, apk_file_path, extract_folder, file_hash)
            if report_result and report_result.returncode == 0:
                event_report_done.set()
            else:
                print(f"{report_script} failed for {apk_file_path}")
                event_report_done.set()
        except Exception as e:
            print(f"Exception running {report_script}: {e}")
            event_report_done.set()

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
        executor.submit(run_report_script)
        if file_size_mb < 100:
            executor.submit(run_clamav_script)
        executor.submit(run_ml_script)

    # Wait for all scripts to complete
    event_report_done.wait()
    if file_size_mb < 100:
        event_clamav_done.wait()
    event_ml_done.wait()

    # Determine final result based on clamav and ml results
    if file_size_mb >= 100:
        # For files >= 100MB, only use ML result and report result
        final_result = "Clean" if not ml_is_malware else "Malware"
    else:
        # For files < 100MB, combine ClamAV and ML results
        if clamav_clean:
            final_result = "Clean"
        elif not clamav_clean and ml_is_malware:
            final_result = "Malware"
        else:
            final_result = "Warning"

    try:
        # Move the reports to their respective directories
        move_files_when_ready(extract_folder, file_hash, f"Result: {final_result}")
    except Exception as e:
        print(f"Exception in moving files: {e}")

    # Keep all APK and TXT files
    keep_files = set(glob.glob(os.path.join(extract_folder, '*.apk')))
    cleanup_directory(extract_folder, keep_files)

    print(f"All scripts have finished for {apk_file_path}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 parallel.py <apk_file_path> <extract_folder> <file_hash>")
        sys.exit(1)

    apk_file_path = sys.argv[1]
    extract_folder = sys.argv[2]
    file_hash = sys.argv[3]

    main(apk_file_path, extract_folder, file_hash)
