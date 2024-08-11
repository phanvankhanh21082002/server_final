import os
import re
import json
import sys

def analyze_manifest(manifest_path, patterns):
    with open(manifest_path, 'r', encoding='utf-8') as file:
        content = file.read()
        results = []
        for pattern_group in patterns:
            message = pattern_group['message']
            for pattern in pattern_group['choice']:
                matches = re.findall(pattern['pattern'], content)
                if matches:
                    results.append((message, matches, pattern['description']))
        return results

def analyze_code(file_path, patterns):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
        results = []
        for pattern_group in patterns:
            message = pattern_group['message']
            for pattern in pattern_group['choice']:
                matches = re.findall(pattern['pattern'], content)
                if matches:
                    results.append((message, matches, pattern['description']))
        return results

def load_rules(json_path):
    with open(json_path, 'r', encoding='utf-8') as file:
        rules = json.load(file)
    code_patterns = []
    manifest_patterns = []
    for rule in rules:
        if rule["type"] == "code":
            code_patterns.append(rule)
        elif rule["type"] == "manifest":
            manifest_patterns.append(rule)
    return code_patterns, manifest_patterns

def find_manifest_file(java_folder):
    for root, _, files in os.walk(java_folder):
        for file in files:
            if file == "AndroidManifest.xml":
                return os.path.join(root, file)
    return None

def main():
    json_path = '../code_static/niap_rules.json'  # Ensure this path is correct
    java_folder = sys.argv[1]  # Path to folder containing Java files

    manifest_path = find_manifest_file(java_folder)
    if not manifest_path:
        print("AndroidManifest.xml not found in the specified folder.")
        sys.exit(1)

    code_patterns, manifest_patterns = load_rules(json_path)

    results = []

    manifest_results = analyze_manifest(manifest_path, manifest_patterns)
    for result in manifest_results:
        results.append(["Manifest", result[0], result[1][0], result[2]])

    for root, _, files in os.walk(java_folder):
        for file in files:
            if file.endswith(".java"):
                file_path = os.path.join(root, file)
                code_results = analyze_code(file_path, code_patterns)
                for result in code_results:
                    results.append(["Code", result[0], result[1][0], result[2]])

    # Filter unique results
    unique_results = []
    seen = set()
    for result in results:
        result_tuple = tuple(result)
        if result_tuple not in seen:
            seen.add(result_tuple)
            unique_results.append(result)

    print(json.dumps(unique_results))

if __name__ == "__main__":
    main()
