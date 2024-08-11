import subprocess
import json
import sys
import os

def run_python_script(script_path, *args):
    try:
        result = subprocess.run(['python3', script_path, *args], capture_output=True, text=True)
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        print(f"Error running {script_path}: {e}")
        return None

def generate_report(apk_file_path, extract_folder, file_hash):
    # Run the scripts and capture their outputs
    file_information_output = run_python_script('file_information.py', apk_file_path)
    api_info_output = run_python_script('read_android_api.py', extract_folder)
    
    # Create HTML content
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>APK Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { text-align: center; }
            .section { margin-bottom: 5px; }
            .section-title { font-size: 18px; margin-bottom: 5px; }
            .box { border: 1px solid #000; padding: 10px; margin-bottom: 5px; }
            .normal { background-color: #d4edda; color: #155724; }
            .dangerous { background-color: #f8d7da; color: #721c24; }
            .unknown { background-color: #e2e3e5; color: #383d41; }
            .info { background-color: #cce5ff; color: #004085; }
            .permission-table, .issue-table { width: 100%; border-collapse: collapse; margin-top: 5px; table-layout: fixed; font-size: 12px; }
            .permission-table th, .permission-table td, .issue-table th, .issue-table td { border: 1px solid #000; padding: 8px; text-align: left; word-wrap: break-word; }
            .permission-table th, .issue-table th { background-color: #f2f2f2; }
            .narrow-column { width: 10%; }
            .medium-column { width: 20%; }
            .wide-column { width: 35%; }
            .extra-wide-column { width: 40%; }
            tr { page-break-inside: avoid; }
            .break-row { border-top: 1px solid #000; }
            .warning { background-color: #fff3cd; color: #856404; }
        </style>
    </head>
    <body>
        <h1>APK Analysis Report</h1>
        <div class="section">
            <div class="section-title">File Information</div>
            <div class="box">
    """

    for key, value in (file_information_output or {}).items():
        html_content += f"<p><strong>{key}:</strong> {value}</p>"

    html_content += """
            </div>
        </div>
        <div class="section">
            <div class="section-title">Android API Information</div>
            <table class="permission-table">
                <tr>
                    <th class="medium-column">API ID</th>
                    <th class="narrow-column">Severity</th>
                    <th class="wide-column">Message</th>
                </tr>
    """

    for api_id, info in (api_info_output or {}).items():
        html_content += f"""
                <tr class="info break-row">
                    <td>{api_id}</td>
                    <td>{info['severity']}</td>
                    <td>{info['message']}</td>
                </tr>
        """

    html_content += """
            </table>
        </div>
    </body>
    </html>
    """

    html_file_path = os.path.join(extract_folder, f"{file_hash}.html")

    with open(html_file_path, "w") as html_file:
         html_file.write(html_content)

    print(f"Report generated and saved to {html_file_path}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 report.py <apk_file_path> <extract_folder> <file_hash>")
        sys.exit(1)

    apk_file_path = sys.argv[1]
    extract_folder = sys.argv[2]
    file_hash = sys.argv[3]
    generate_report(apk_file_path, extract_folder, file_hash)
