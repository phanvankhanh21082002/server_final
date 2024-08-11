import xml.etree.ElementTree as ET
import json
import os
import sys

def find_manifest_file(extract_folder):
    for root, dirs, files in os.walk(extract_folder):
        if 'AndroidManifest.xml' in files:
            return os.path.join(root, 'AndroidManifest.xml')
    return None

def parse_manifest(file_path):
    try:
        # Load and parse the AndroidManifest.xml
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Namespace mapping to simplify finding elements
        ns = {'android': 'http://schemas.android.com/apk/res/android'}

        # List to hold browsable activities information
        browsable_activities = []

        # Iterate over all activities in the manifest
        for activity in root.findall('application/activity', ns):
            activity_name = activity.get('{http://schemas.android.com/apk/res/android}name')
            # Check each activity for intent filters
            for intent_filter in activity.findall('intent-filter', ns):
                action_view = intent_filter.find("action[@android:name='android.intent.action.VIEW']", ns)
                category_browsable = intent_filter.find("category[@android:name='android.intent.category.BROWSABLE']", ns)
                
                if action_view is not None and category_browsable is not None:
                    # If both VIEW action and BROWSABLE category are present
                    data = intent_filter.find('data', ns)
                    if data is not None:
                        scheme = data.get('{http://schemas.android.com/apk/res/android}scheme')
                        host = data.get('{http://schemas.android.com/apk/res/android}host')
                        path = data.get('{http://schemas.android.com/apk/res/android}path')
                        browsable_activities.append({
                            'Activity': activity_name,
                            'Scheme': scheme,
                            'Host': host,
                            'Path': path
                        })

        return browsable_activities

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
        activities = parse_manifest(manifest_file)
        print(json.dumps(activities, indent=2))
    else:
        print("AndroidManifest.xml not found in the specified folder.")

if __name__ == "__main__":
    main()
