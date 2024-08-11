import subprocess
import json
import sys

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e.stderr}")
        return None

def verify_apk_signature(apk_path):
    apksigner_path = 'apksigner'
    apksigner_command = [apksigner_path, 'verify', '--print-certs', '--verbose', apk_path]
    apksigner_output = run_command(apksigner_command)
    return apksigner_output

def get_filtered_cert_info(cert_data):
    filtered_lines = []

    for line in cert_data.splitlines():
        if "Verified using" in line:
            filtered_lines.append(line.replace("Verified using ", ""))
        elif "Signer" in line:
            filtered_lines.append(line.replace("Signer ", ""))
        elif "WARNING: META-INF" not in line:
            filtered_lines.append(line)

    return "\n".join(filtered_lines)

def get_certificate_info(apk_path):
    apksigner_output = verify_apk_signature(apk_path)
    if apksigner_output:
        filtered_info = get_filtered_cert_info(apksigner_output)
        return {"certificate_info": filtered_info}
    else:
        return {"error": "Verification Failed"}

def main():
    apk_path = sys.argv[1]
    cert_info = get_certificate_info(apk_path)
    print(json.dumps(cert_info))

if __name__ == "__main__":
    main()
