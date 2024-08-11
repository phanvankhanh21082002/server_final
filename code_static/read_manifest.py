import xml.etree.ElementTree as ET
import json
import os
import sys
from permissions_database import MANIFEST_PERMISSION

def find_manifest_file(extract_folder):
    for root, dirs, files in os.walk(extract_folder):
        if 'AndroidManifest.xml' in files:
            return os.path.join(root, 'AndroidManifest.xml')
    return None

def parse_android_manifest(file_path):
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        permissions = root.findall(".//uses-permission")

        unique_permissions = set()
        for perm in permissions:
            perm_name = perm.get('{http://schemas.android.com/apk/res/android}name')
            unique_permissions.add(perm_name)

        permissions_info = []
        for perm_name in unique_permissions:
            if perm_name in MANIFEST_PERMISSION:
                perm_info = MANIFEST_PERMISSION[perm_name]
                level = perm_info[0]
                description = perm_info[1]
                details = perm_info[2]
                permissions_info.append({
                    "name": perm_name,
                    "level": level,
                    "description": description,
                    "details": details
                })
            else:
                permissions_info.append({
                    "name": perm_name,
                    "level": "unknown",
                    "description": "Special Permission - No additional information available.",
                    "details": ""
                })

        return permissions_info

    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return []
    except FileNotFoundError:
        print("The specified file was not found.")
        return []

def main():
    extract_folder = sys.argv[1]
    manifest_file = find_manifest_file(extract_folder)
    if manifest_file:
        permissions_info = parse_android_manifest(manifest_file)
        print(json.dumps(permissions_info))
    else:
        print("AndroidManifest.xml not found in the specified folder.")

if __name__ == "__main__":
    main()
