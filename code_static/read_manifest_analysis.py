import xml.etree.ElementTree as ET
import subprocess
import re
import json
import os
import sys

# Assume MANIFEST_DESC is defined elsewhere and imported here
from manifest_database import MANIFEST_DESC

# Constants for Android API levels
ANDROID_4_2_LEVEL = 17
ANDROID_5_0_LEVEL = 21
ANDROID_8_0_LEVEL = 26
ANDROID_9_0_LEVEL = 28
ANDROID_10_0_LEVEL = 29

# Descriptions for components
DESCRIPTIONS = {
    'Activity': 'This flag allows anyone to backup your application data via adb. It allows users who have enabled USB debugging to copy application data off of the device.',
    'Service': 'A Service is found to be shared with other apps on the device therefore leaving it accessible to any other application on the device. It is protected by a permission which is not defined in the analysed application. As a result, the protection level of the permission should be checked where it is defined. If it is set to normal or dangerous, a malicious application can request and obtain the permission and interact with the component. If it is set to signature, only applications signed with the same certificate can obtain the permission.',
    'Receiver': 'A Receiver is found to be shared with other apps on the device therefore leaving it accessible to any other application on the device. It is protected by a permission which is not defined in the analysed application. As a result, the protection level of the permission should be checked where it is defined. If it is set to normal or dangerous, a malicious application can request and obtain the permission and interact with the component. If it is set to signature, only applications signed with the same certificate can obtain the permission.'
}

# Map for Android API levels to version names
ANDROID_API_LEVEL_MAP = {
    '1': '1.0',
    '2': '1.1',
    '3': '1.5',
    '4': '1.6',
    '5': '2.0-2.1',
    '8': '2.2-2.2.3',
    '9': '2.3-2.3.2',
    '10': '2.3.3-2.3.7',
    '11': '3.0',
    '12': '3.1',
    '13': '3.2-3.2.6',
    '14': '4.0-4.0.2',
    '15': '4.0.3-4.0.4',
    '16': '4.1-4.1.2',
    '17': '4.2-4.2.2',
    '18': '4.3-4.3.1',
    '19': '4.4-4.4.4',
    '20': '4.4W-4.4W.2',
    '21': '5.0-5.0.2',
    '22': '5.1-5.1.1',
    '23': '6.0-6.0.1',
    '24': '7.0',
    '25': '7.1-7.1.2',
    '26': '8.0',
    '27': '8.1',
    '28': '9',
    '29': '10',
    '30': '11',
    '31': '12',
    '32': '12L',
    '33': '13',
    '34': '14',
}

def get_sdk_info(apk_path):
    # Use aapt tool to get SDK info from APK
    result = subprocess.run(['aapt', 'dump', 'badging', apk_path], stdout=subprocess.PIPE, text=True)
    aapt_output = result.stdout

    # Use regex to extract minSdkVersion and targetSdkVersion
    sdk_info = {}
    min_sdk_match = re.search(r"sdkVersion:'(\d+)'", aapt_output)
    target_sdk_match = re.search(r"targetSdkVersion:'(\d+)'", aapt_output)

    if min_sdk_match:
        sdk_info['minSdkVersion'] = min_sdk_match.group(1)
    if target_sdk_match:
        sdk_info['targetSdkVersion'] = target_sdk_match.group(1)

    return sdk_info

def find_manifest_file(extract_folder):
    for root, dirs, files in os.walk(extract_folder):
        if 'AndroidManifest.xml' in files:
            return os.path.join(root, 'AndroidManifest.xml')
    return None

def parse_manifest_file(file_path, sdk_info):
    # Read XML file
    tree = ET.parse(file_path)
    root = tree.getroot()
    namespace = {'android': 'http://schemas.android.com/apk/res/android'}
    ns = 'http://schemas.android.com/apk/res/android'  # Namespace for android attributes

    # Get information from the <application> tag
    application_info = {}
    application_tag = root.find(".//application", namespace)
    if application_tag is not None:
        # Check and extract attributes from the <application> tag
        application_info['clear_text_traffic'] = application_tag.get(f'{{{ns}}}usesCleartextTraffic') == 'true'
        application_info['direct_boot_aware'] = application_tag.get(f'{{{ns}}}directBootAware') == 'true'
        network_security_config = application_tag.get(f'{{{ns}}}networkSecurityConfig')
        application_info['has_network_security'] = network_security_config if network_security_config else 'false'
        application_info['app_is_debuggable'] = application_tag.get(f'{{{ns}}}debuggable') == 'true'
        allow_backup = application_tag.get(f'{{{ns}}}allowBackup')
        application_info['app_allowbackup'] = 'true' if allow_backup == 'true' else 'false' if allow_backup == 'false' else 'not set'
        application_info['app_in_test_mode'] = application_tag.get(f'{{{ns}}}testOnly') == 'true'
        
        backupDisabled = False
        if application_tag.get(f'{ns}:allowBackup') == 'true':
            application_info['app_allowbackup'] = 'true'
        elif application_tag.get(f'{ns}:allowBackup') == 'false':
            backupDisabled = True
        else:
            if not backupDisabled:
                application_info['allowbackup_not_set'] = 'not set'
    # Add SDK info to application_info
    application_info.update(sdk_info)

    # Structure to store component information
    components = {
        'Activity': [],
        'Service': [],
        'Receiver': [],
        'Provider': []
    }

    exported_protected_permission = {
        'normal': [],
        'dangerous': [],
        'signature': [],
        'signatureOrSystem': [],
        'not_defined': []
    }

    vulnerabilities = []

    for itemname, path in {
        'Activity': ".//activity",
        'Activity-Alias': ".//activity-alias",
        'Service': ".//service",
        'Receiver': ".//receiver",
        'Provider': ".//provider"
    }.items():
        for component in root.findall(path, namespace):
            exported = component.get(f'{{{namespace["android"]}}}exported', 'false')
            launchmode = component.get(f'{{{namespace["android"]}}}launchMode')
            task_affinity = component.get(f'{{{namespace["android"]}}}taskAffinity')
            name = component.get(f'{{{namespace["android"]}}}name')
            protection_level = component.get(f'{{{namespace["android"]}}}protectionLevel')

            if exported == 'true':
                component_info = {
                    'name': name,
                    'exported': exported,
                    'launchmode': launchmode,
                    'task_affinity': task_affinity,
                    'protectionLevel': protection_level,
                    'description': DESCRIPTIONS.get(itemname, '')
                }
                components[itemname].append(component_info)

                # Categorize by protection level
                if protection_level:
                    if protection_level == 'normal':
                        exported_protected_permission['normal'].append(component_info)
                    elif protection_level == 'dangerous':
                        exported_protected_permission['dangerous'].append(component_info)
                    elif protection_level == 'signature':
                        exported_protected_permission['signature'].append(component_info)
                    elif protection_level == 'signatureOrSystem':
                        exported_protected_permission['signatureOrSystem'].append(component_info)
                    else:
                        exported_protected_permission['not_defined'].append(component_info)

            # Check for grant-uri-permission vulnerabilities
            for granturi in component.findall(".//grant-uri-permission", namespace):
                if granturi.get(f'{{{ns}}}pathPrefix') == '/':
                    vulnerabilities.append(
                        ('improper_provider_permission', ('pathPrefix=/',), ()))
                elif granturi.get(f'{{{ns}}}path') == '/':
                    vulnerabilities.append(('improper_provider_permission', ('path=/',), ()))
                elif granturi.get(f'{{{ns}}}pathPattern') == '*':
                    vulnerabilities.append(('improper_provider_permission', ('path=*',), ()))

    # Check for data elements anywhere in the manifest
    for data in root.findall(".//data", namespace):
        if data.get(f'{{{ns}}}scheme') == 'android_secret_code':
            xmlhost = data.get(f'{{{ns}}}host')
            vulnerabilities.append(('dialer_code_found', (xmlhost,), ()))

        elif data.get(f'{{{ns}}}port'):
            dataport = data.get(f'{{{ns}}}port')
            vulnerabilities.append(('sms_receiver_port_found', (dataport,), ()))

    # Check for intent-filter elements anywhere in the manifest
    for intent in root.findall(".//intent-filter", namespace):
        priority = intent.get(f'{{{ns}}}priority')
        if priority and priority.isdigit():
            value = priority
            if int(value) > 100:
                vulnerabilities.append(('high_intent_priority_found', (value,), ()))

    # Check for action elements anywhere in the manifest
    for action in root.findall(".//action", namespace):
        priority = action.get(f'{{{ns}}}priority')
        if priority and priority.isdigit():
            value = priority
            if int(value) > 100:
                vulnerabilities.append(('high_action_priority_found', (value,), ()))

    # Update application_info with exported protected permission details
    for level, details in exported_protected_permission.items():
        if level == 'normal':
            application_info['exported_protected_permission_normal'] = details
        elif level == 'dangerous':
            application_info['exported_protected_permission_dangerous'] = details
        elif level == 'signature':
            application_info['exported_protected_permission_signature'] = details
        elif level == 'signatureOrSystem':
            application_info['exported_protected_permission_signatureOrSystem'] = details
        else:
            application_info['exported_protected_permission_not_defined'] = details

    return application_info, components, vulnerabilities

def display_manifest_details(application_info, components_info, vulnerabilities):
    json_output = []

    # Add application information to JSON
    for key, value in application_info.items():
        if value == 'true':
            if key in MANIFEST_DESC:
                desc = MANIFEST_DESC[key]
                json_output.append({
                    'name': desc['name'],
                    'severity': 'warning',
                    'description': desc['description']
                })

    # Check for vulnerable OS versions
    min_sdk = application_info.get('minSdkVersion')
    if min_sdk:
        android_version = ANDROID_API_LEVEL_MAP.get(min_sdk, 'XX')
        if int(min_sdk) < ANDROID_8_0_LEVEL:
            desc = MANIFEST_DESC['vulnerable_os_version']
            json_output.append({
                'name': desc['name'] % (android_version, min_sdk),
                'severity': 'warning',
                'description': desc['description']
            })

        elif int(min_sdk) < ANDROID_10_0_LEVEL:
            desc = MANIFEST_DESC['vulnerable_os_version2']
            json_output.append({
                'name': desc['name'] % (android_version, min_sdk),
                'severity': 'warning',
                'description': desc['description']
            })

    # Check for task hijacking vulnerabilities
    target_sdk = application_info.get('targetSdkVersion')
    if target_sdk:
        for comp_type, components in components_info.items():
            for component in components:
                name = component['name']
                exported = component['exported']
                launchmode = component['launchmode']
                task_affinity = component['task_affinity']

                if int(target_sdk) < ANDROID_9_0_LEVEL and launchmode == 'singleTask':
                    desc = MANIFEST_DESC['task_hijacking']
                    json_output.append({
                        'name': desc['name'],
                        'severity': 'warning',
                        'description': desc['description']
                    })

                if int(target_sdk) < ANDROID_10_0_LEVEL and exported == 'true' and (launchmode != 'singleInstance' or task_affinity != ''):
                    desc = MANIFEST_DESC['task_hijacking2']
                    json_output.append({
                        'name': desc['name'],
                        'severity': 'warning',
                        'description': desc['description']
                    })

    # Add vulnerabilities
    if vulnerabilities:
        for vulnerability in vulnerabilities:
            desc = MANIFEST_DESC[vulnerability[0]]
            json_output.append({
                'name': desc['name'],
                'severity': 'warning',
                'description': desc['description']
            })

    # Add component information
    for comp_type, components in components_info.items():
        for component in components:
            json_output.append({
                'name': f"{comp_type}: {component['name']} [android:exported=true]",
                'severity': 'warning',
                'description': component['description']
            })

    # Display in JSON format
    print(json.dumps(json_output, indent=2))

if __name__ == "__main__":
    apk_path = sys.argv[1]
    extract_folder = sys.argv[2]
    manifest_path = find_manifest_file(extract_folder)

    if manifest_path:
        sdk_info = get_sdk_info(apk_path)
        application_info, components_info, vulnerabilities = parse_manifest_file(manifest_path, sdk_info)
        display_manifest_details(application_info, components_info, vulnerabilities)
    else:
        print("AndroidManifest.xml not found in the provided extract folder.")

