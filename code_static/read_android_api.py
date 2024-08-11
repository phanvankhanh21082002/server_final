import yaml
import subprocess
import os
import json
import sys

def flatten(l):
    """Flatten a list of strings and lists into a single list of strings"""
    flat_list = []
    for item in l:
        if isinstance(item, list):
            flat_list.extend(flatten(item))  # Recursive call for nested lists
        else:
            flat_list.append(item)
    return flat_list

def run_grep_with_bash(yaml_path, directory):
    # Load YAML data
    with open(yaml_path, 'r') as file:
        data = yaml.safe_load(file)

    results = {}  # Dictionary to store results

    # Loop through each entry in the YAML data
    for item in data:
        api_id = item['id']
        severity = item['severity']
        message = item['message']
        pattern = item['pattern']
        # Flatten the pattern list if it's nested
        if isinstance(pattern, list):
            pattern = flatten(pattern)
        # Combine patterns for grep using OR
        pattern = "|".join([p.replace('|', '\\|') for p in pattern])  # Ensure to escape '|'

        # Build the grep command
        cmd = f"grep -rEl '{pattern}' {directory}"
        
        try:
            # Execute the grep command
            output = subprocess.run(cmd, shell=True, text=True, capture_output=True, check=True)
            files = [os.path.relpath(file, directory).replace(os.sep, '/') for file in output.stdout.strip().split('\n') if file]  # Convert to relative paths
            if files:  # Check if there's any result
                results[api_id] = {
                    'severity': severity,
                    'message': message
                }
                #print(f"Found: {api_id} (Severity: {severity}, Message: {message})")
        except subprocess.CalledProcessError:
            # No matches found for this pattern
            continue
        except Exception as e:
            print(f"An error occurred: {e}")

    return results

def main():
    extract_folder = sys.argv[1]
    yaml_path = '../code_static/android_api.yaml'
    results = run_grep_with_bash(yaml_path, extract_folder)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
